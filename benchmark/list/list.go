package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/s2"
	"golang.org/x/time/rate"
	"k8s.io/client-go/rest"
)

func NewLister(clients []*http.Client, pathTemplate string, config *rest.Config, qps float32, serverURL *url.URL, params string, namespaces int, acceptEncoding string, serial bool) *lister {
	return &lister{
		clients:        clients,
		pathTemplate:   pathTemplate,
		config:         config,
		serverURL:      serverURL,
		params:         params,
		namespaces:     namespaces,
		acceptEncoding: acceptEncoding,
		stats:          &stats{},
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
	stats          *stats
}

func (l *lister) makeRequest(i int) {
	path := fmt.Sprintf(l.pathTemplate, i%l.namespaces)
	if l.params != "" {
		path = fmt.Sprintf("%s?%s", path, l.params)
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
	buf := bytes.NewBuffer(make([]byte, 0, 1<<30)) // 1GB
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
		panic(fmt.Sprintf("Got bad status code: %v\n", resp.Status))
	}
	if resp.Header.Get("Content-Type") != l.config.ContentType || (strings.HasSuffix(l.config.ContentType, "gzip") && resp.Header.Get("Content-Encoding") != "gzip") {
		panic(fmt.Sprintf("Got bad content type: %q, expected %q\n", resp.Header.Get("Content-Type"), l.config.ContentType))
	}
	var reader io.Reader = resp.Body
	// if resp.Header.Get("Content-Encoding") == "s2" {
	// 	reader = s2.NewReader(resp.Body)
	// }
	written, err := io.Copy(buf, reader)
	if err != nil {
		return
	}
	latency := time.Since(start)
	go func ()  {
		var uncompressed int64
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			gzipReader, err := gzip.NewReader(buf)
			if err != nil {
				panic(err)
			}
			uncompressed, err = io.Copy(io.Discard, gzipReader)
			if err != nil {
				panic(err)
			}
		case "s2":
			uncompressed, err = io.Copy(io.Discard, s2.NewReader(buf))
			if err != nil {
				panic(err)
			}
		default:
			uncompressed = written
		}
		l.stats.Record(latency, written, uncompressed)
	}()
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

type stats struct {
	mu         sync.Mutex
	latencies  []time.Duration
	latencySum  time.Duration
	writtenSize    int64
	decompressedSize int64
}

func (s *stats) Record(latency time.Duration, written, decompressed int64) {
	s.mu.Lock()
	s.latencySum += latency
	s.latencies = append(s.latencies, latency)
	s.writtenSize += written
	s.decompressedSize += decompressed 
	s.mu.Unlock()
}

func (s *stats) printStats(testDuration time.Duration) {
	fmt.Printf("QPS: %.2f\n", float64(len(s.latencies))/testDuration.Seconds())
	if len(s.latencies) == 0 {
		return
	}
	fmt.Printf("Request Count: %v\n", len(s.latencies))
	fmt.Printf("Written Size Average: %v B\n", s.writtenSize/int64(len(s.latencies)))
	fmt.Printf("Decompressed Size Average: %v B\n", s.decompressedSize/int64(len(s.latencies)))
	fmt.Printf("Compression Ratio: %.2f\n", float64(s.decompressedSize)/float64(s.writtenSize))
	fmt.Printf("Throughput: %.2f MB/s\n", float64(s.decompressedSize)/1000/1000/s.latencySum.Seconds())
	fmt.Printf("Latency Average: %.3f seconds\n", s.latencySum.Seconds() / float64(len(s.latencies)))
	sort.Slice(s.latencies, func(i, j int) bool {
		return s.latencies[i] < s.latencies[j]
	})
	fmt.Printf("Latency 50%%ile: %.3f seconds\n", s.latencies[len(s.latencies)/2].Seconds())
	fmt.Printf("Latency 90%%ile: %.3f seconds\n", s.latencies[len(s.latencies)*9/10].Seconds())
	if len(s.latencies) > 20 {
		fmt.Printf("Latency 95%%ile: %.3f seconds\n", s.latencies[len(s.latencies)*19/20].Seconds())
	}	
	if len(s.latencies) > 100 {
		fmt.Printf("Latency 99%%ile: %.3f seconds\n", s.latencies[len(s.latencies)*99/100].Seconds())
	}
}
