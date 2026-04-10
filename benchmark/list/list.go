package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	// jsonv2 "github.com/go-json-experiment/json"

	// "github.com/andybalholm/brotli"
	// kgzip "github.com/klauspost/compress/gzip"
	// "github.com/klauspost/compress/s2"
	// "github.com/klauspost/compress/zstd"
	// "github.com/klauspost/pgzip"
	// "github.com/pierrec/lz4/v4"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type ListOptions struct {
	Resource             string
	ResourceVersion      string
	ResourceVersionMatch string
	ContinueToken        string
	Pretty               bool
	ContentType          string
	Limit                int
	Filter               bool
	Config               *rest.Config
	QPS                  float32
	Namespaces           int
	AcceptEncoding       string
	Serial               bool
	WatchList            bool
	Decode               string
}

func NewLister(clients []*http.Client, serverURL *url.URL, options ListOptions) (*lister, error) {
	var pathTemplate string
	switch options.Resource {
	case "secret":
		pathTemplate = "/api/v1/namespaces/%d/secrets"
	case "configmap":
		pathTemplate = "/api/v1/namespaces/%d/configmaps"
	case "pod":
		pathTemplate = "/api/v1/namespaces/%d/pods"
	case "cr":
		pathTemplate = "/apis/stable.example.com/v1/namespaces/%d/crontabs"
	default:
		return nil, fmt.Errorf("resource should be set to \"configmap\", \"pod\" or \"cr\"")
	}
	params := []string{}
	if options.ResourceVersion != "" {
		params = append(params, fmt.Sprintf("resourceVersion=%s", options.ResourceVersion))
	}
	if options.ResourceVersionMatch != "" {
		params = append(params, fmt.Sprintf("resourceVersionMatch=%s", options.ResourceVersionMatch))
	}
	if options.ContinueToken != "" {
		params = append(params, fmt.Sprintf("continue=%s", options.ContinueToken))
	}
	if options.Pretty {
		if options.ContentType != "json" {
			panic("Pretty only supported for JSON")
		}
		params = append(params, "pretty=1")
	}
	if options.Limit != 0 {
		if options.Limit < 0 {
			panic("limit cannot be negative")
		}
		params = append(params, fmt.Sprintf("limit=%d", options.Limit))
	}
	if options.Filter {
		params = append(params, "labelSelector=app%3D0")
	}
	paramStr := strings.Join(params, "&")
	negotiatedSerializer := options.Config.NegotiatedSerializer
	if negotiatedSerializer == nil {
		negotiatedSerializer = scheme.Codecs
	}
	gv := metav1.SchemeGroupVersion
	if options.Config.GroupVersion != nil {
		gv = *options.Config.GroupVersion
	}

	return &lister{
		clients:      clients,
		pathTemplate: pathTemplate,
		params:       paramStr,
		serverURL:    serverURL,
		options:      options,
		stats:        &stats{},
		negotiator:   runtime.NewClientNegotiator(negotiatedSerializer, gv),
		decoder:      scheme.Codecs.DecoderToVersion(scheme.Codecs.UniversalDeserializer(), gv),
	}, nil
}

func (l *lister) Run(serial bool, qps float32) *stats {
	start := time.Now()
	if serial {
		l.runSerial(start, testDuration)
	} else {
		l.runParallel(start, testDuration, qps)
	}
	return l.stats
}

type lister struct {
	options      ListOptions
	clients      []*http.Client
	pathTemplate string
	serverURL    *url.URL
	params       string
	stats        *stats
	negotiator   runtime.ClientNegotiator
	decoder      runtime.Decoder
}

func (l *lister) makeRequest(i int) {
	path := fmt.Sprintf(l.pathTemplate, i%l.options.Namespaces)
	if l.options.WatchList {
		if l.params != "" {
			path = fmt.Sprintf("%s?%s&watch=true&allowWatchBookmarks=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan", path, l.params)
		} else {
			path = fmt.Sprintf("%s?watch=true&allowWatchBookmarks=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan", path)
		}
	} else {
		if l.params != "" {
			path = fmt.Sprintf("%s?%s", path, l.params)
		}
	}

	url, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	url.Host = l.serverURL.Host
	url.Scheme = l.serverURL.Scheme
	reqCtx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", url.String(), nil)
	if err != nil {
		panic(fmt.Sprintf("Got error creating a request: %v\n", err))
	}
	req.Header.Set("Accept", l.options.ContentType)
	req.Header.Set("Accept-Encoding", l.options.AcceptEncoding)
	start := time.Now()
	resp, err := l.clients[i%len(l.clients)].Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	readingHeaderLatency := time.Since(start)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		fmt.Print("Too many requests\n")
		return
	}
	if resp.StatusCode == 504 {
		fmt.Print("Bad gateway\n")
		return
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent {
		body, err := io.ReadAll(resp.Body)
		panic(fmt.Sprintf("Got bad status code: %v, body: %s, err: %v\n", resp.Status, string(body), err))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), l.options.ContentType) {
		panic(fmt.Sprintf("Got bad content type: %q, expected %q\n", resp.Header.Get("Content-Type"), l.options.ContentType))
	}
	contentType := resp.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		panic(fmt.Sprintf("unexpected content type from the server: %q: %v", contentType, err))
	}
	responseReadingStats := &TraceReader{next: resp.Body}
	decompressedReader, err := decompress(responseReadingStats, l.options.AcceptEncoding)
	if err != nil {
		panic(fmt.Sprintf("Error decompressing response: %v\n", err))
	}
	decompressionStats := &TraceReader{next: decompressedReader}
	var bufferingDuration time.Duration
	if l.options.WatchList {
		err = l.handleWatchList(decompressionStats, mediaType, params)
	} else {
		bufferingDuration, err = l.handleList(decompressionStats, mediaType)
	}
	requestLatency := time.Since(start)
	l.stats.RecordReadingHeaders(readingHeaderLatency)
	l.stats.RecordReadingResponse(responseReadingStats.duration, responseReadingStats.bytes)
	l.stats.RecordDecompressing(decompressionStats.duration-responseReadingStats.duration, decompressionStats.bytes)
	if bufferingDuration != 0 {
		l.stats.RecordBuffering(bufferingDuration - decompressionStats.duration)
		l.stats.RecordDecodingBody(requestLatency - bufferingDuration - readingHeaderLatency)
	} else {
		l.stats.RecordDecodingBody(requestLatency - readingHeaderLatency - decompressionStats.duration)
	}
	l.stats.RecordRequestLatency(requestLatency)
	if err != nil {
		panic(fmt.Sprintf("Error handling list: %v\n", err))
	}
}

func decompress(compressedBody io.Reader, contentEncoding string) (io.Reader, error) {
	var reader io.Reader
	switch contentEncoding {
	case "gzip":
		var err error
		reader, err = gzip.NewReader(compressedBody)
		if err != nil {
			return nil, fmt.Errorf("Error creating gzip reader: %v", err)
		}
	// case "kgzip":
	// 	var err error
	// 	reader, err = kgzip.NewReader(compressedBody)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Error creating gzip reader: %v", err)
	// 	}
	// case "pgzip":
	// 	var err error
	// 	reader, err = pgzip.NewReader(compressedBody)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Error creating gzip reader: %v", err)
	// 	}
	// case "s2":
	// 	reader = s2.NewReader(compressedBody)
	// case "zstd":
	// 	var err error
	// 	reader, err = zstd.NewReader(compressedBody)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Error creating zstd reader: %v", err)
	// 	}
	// case "br":
	// 	reader = brotli.NewReader(compressedBody)
	// case "lz4":
	// 	reader = lz4.NewReader(compressedBody)
	case "":
		reader = compressedBody
	default:
		return nil, fmt.Errorf("Got bad content encoding: %q, expected gzip, s2, zstd, br, or lz4", contentEncoding)
	}
	return reader, nil
}

func NewTraceReader(name string, next io.Reader) *TraceReader {
	return &TraceReader{
		name: name,
		next: next,
	}
}

type TraceReader struct {
	name     string
	duration time.Duration
	bytes    int64
	next     io.Reader
}

func (t *TraceReader) Read(p []byte) (n int, err error) {
	start := time.Now()
	n, err = t.next.Read(p)
	t.duration += time.Since(start)
	t.bytes += int64(n)
	return n, err
}

func (l *lister) handleList(reader io.Reader, mediaType string) (bufferDuration time.Duration, err error) {
	buf := bytes.NewBuffer(nil)
	var out interface{}
	switch l.options.Resource {
	case "pod":
		out = corev1.PodList{}
	case "secret":
		out = corev1.SecretList{}
	default:
		return bufferDuration, fmt.Errorf("Unhandled resource: %q", l.options.Resource)
	}
	start := time.Now()
	switch l.options.Decode {
	case "decoder", "v1", "v2":
		_, err := io.Copy(buf, reader)
		if err != nil {
			return bufferDuration, err
		}
		bufferDuration = time.Since(start)
	case "v2stream":
	default:
		return bufferDuration, fmt.Errorf("Got bad decode option: %q, expected v1, v2, or v2stream", l.options.Decode)
	}

	decode := l.options.Decode
	if mediaType != "application/json" {
		decode = "decoder"
	}
	switch decode {
	case "decoder":
		_, _, err := l.decoder.Decode(buf.Bytes(), nil, nil)
		return bufferDuration, err
	case "v1":
		err := json.Unmarshal(buf.Bytes(), &out)
		return bufferDuration, err
	// case "v2":
	// 	err := jsonv2.Unmarshal(buf.Bytes(), &out)
	// 	return bufferDuration, err
	// case "v2stream":
	// 	err := jsonv2.UnmarshalRead(reader, &out)
	// 	return bufferDuration, err
	default:
		return bufferDuration, fmt.Errorf("Got bad decode option: %q, expected v1, v2, or v2stream", l.options.Decode)
	}
}

func (l *lister) handleWatchList(reader io.Reader, mediaType string, params map[string]string) error {
	_, streamingSerializer, framer, err := l.negotiator.StreamDecoder(mediaType, params)
	if err != nil {
		return err
	}
	frameReader := framer.NewFrameReader(io.NopCloser(reader))
	decoder := streaming.NewDecoder(frameReader, streamingSerializer)

	for {
		var event metav1.WatchEvent
		_, _, err := decoder.Decode(nil, &event)
		if err != nil {
			if err == io.EOF {
				panic("Stream ended before getting bookmark")
			}
			return err
		}
		if event.Type == string(watch.Bookmark) {
			return nil
		}
	}
}

func (l *lister) runSerial(start time.Time, testDuration time.Duration) {
	index := 0
	for time.Since(start) < testDuration {
		l.makeRequest(index)
		index++
	}
}

func (l *lister) runParallel(start time.Time, testDuration time.Duration, qps float32) {
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(testDuration))
	defer cancel()
	takeN := int(math.Ceil(float64(qps) / 500))
	rateLimiter := rate.NewLimiter(rate.Limit(qps), takeN)
	var wg sync.WaitGroup
	index := 0
	for time.Since(start) < testDuration {
		err := rateLimiter.WaitN(ctx, takeN)
		if err != nil {
			continue
		}
		for j := 0; j < takeN; j++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				l.makeRequest(i)
			}(index)
			index++
		}
	}
	wg.Wait()
}
