package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func NewLister(clients []*http.Client, pathTemplate string, config *rest.Config, qps float32, serverURL *url.URL, params string, namespaces int, acceptEncoding string, serial bool, watchList bool) *lister {
	negotiatedSerializer := config.NegotiatedSerializer
	if negotiatedSerializer == nil {
		negotiatedSerializer = scheme.Codecs
	}
	gv := metav1.SchemeGroupVersion
	if config.GroupVersion != nil {
		gv = *config.GroupVersion
	}
	return &lister{
		clients:        clients,
		pathTemplate:   pathTemplate,
		config:         config,
		serverURL:      serverURL,
		params:         params,
		namespaces:     namespaces,
		acceptEncoding: acceptEncoding,
		watchList:      watchList,
		stats:          &stats{},
		negotiator:     runtime.NewClientNegotiator(negotiatedSerializer, gv),
		decoder:        scheme.Codecs.DecoderToVersion(scheme.Codecs.UniversalDeserializer(), gv),
	}
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
	clients        []*http.Client
	pathTemplate   string
	config         *rest.Config
	serverURL      *url.URL
	params         string
	namespaces     int
	acceptEncoding string
	watchList      bool
	stats          *stats
	negotiator     runtime.ClientNegotiator
	decoder        runtime.Decoder
}

func (l *lister) makeRequest(i int) {
	path := fmt.Sprintf(l.pathTemplate, i%l.namespaces)
	if l.watchList {
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
	req.Header.Set("Accept", l.config.ContentType)
	req.Header.Set("Accept-Encoding", l.acceptEncoding)
	start := time.Now()
	resp, err := l.clients[i%len(l.clients)].Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
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
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), l.config.ContentType) {
		panic(fmt.Sprintf("Got bad content type: %q, expected %q\n", resp.Header.Get("Content-Type"), l.config.ContentType))
	}
	contentType := resp.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		panic(fmt.Sprintf("unexpected content type from the server: %q: %v", contentType, err))
	}

	compressedBody := &countingReader{r: resp.Body}
	var reader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		var err error
		reader, err = pgzip.NewReader(compressedBody)
		if err != nil {
			panic(fmt.Sprintf("Error creating gzip reader: %v\n", err))
		}
	case "s2":
		reader = s2.NewReader(compressedBody)
	case "zstd":
		var err error
		reader, err = zstd.NewReader(compressedBody)
		if err != nil {
			panic(fmt.Sprintf("Error creating zstd reader: %v\n", err))
		}
	case "br":
		reader = brotli.NewReader(compressedBody)
	case "lz4":
		reader = lz4.NewReader(compressedBody)
	case "":
		reader = compressedBody
	default:
		panic(fmt.Sprintf("Got bad content encoding: %q, expected gzip, s2, zstd, br, or lz4\n", resp.Header.Get("Content-Encoding")))
	}
	decompressedBody := &countingReader{r: reader}

	switch l.watchList {
	case true:
		err = l.handleWatchList(resp, decompressedBody, start, mediaType, params)
	case false:
		err = l.handleList(resp, decompressedBody, start)
	}
	if err != nil {
		panic(fmt.Sprintf("Error handling list: %v\n", err))
	}
	latency := time.Since(start)
	l.stats.Record(latency, compressedBody.n, decompressedBody.n)
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	r.n += int64(n)
	return
}

func (l *lister) handleList(resp *http.Response, reader io.Reader, start time.Time) error {
	buf := bytes.NewBuffer(nil)
	_, err := io.Copy(buf, reader)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return err
	}
	_, _, err = l.decoder.Decode(buf.Bytes(), nil, nil)
	return err
}

func (l *lister) handleWatchList(resp *http.Response, reader io.Reader, start time.Time, mediaType string, params map[string]string) error {
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