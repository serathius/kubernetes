package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/util/slice"
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
	written, err := io.Copy(io.Discard, reader)
	if err != nil {
		return
	}
	latency := time.Since(start)
	l.stats.Record(latency, written)
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
	latencies  []int64
	latencySum int64
	sizeSum    int64
}

func (s *stats) Record(latency time.Duration, written int64) {
	s.mu.Lock()
	s.latencySum += int64(latency)
	s.latencies = append(s.latencies, int64(latency))
	s.sizeSum += written
	s.mu.Unlock()
}

func (s *stats) printStats(testDuration time.Duration) {
	fmt.Printf("QPS: %.2f\n", float64(len(s.latencies))/testDuration.Seconds())
	if len(s.latencies) == 0 {
		return
	}
	fmt.Printf("Request Count: %v\n", len(s.latencies))
	fmt.Printf("Size Average: %v\n", s.sizeSum/int64(len(s.latencies)))
	fmt.Printf("Latency Average: %v\n", time.Duration(s.latencySum/int64(len(s.latencies))))
	slice.SortInts64(s.latencies)
	fmt.Printf("Latency 50%%ile: %v\n", time.Duration(s.latencies[len(s.latencies)/2]))
	fmt.Printf("Latency 90%%ile: %v\n", time.Duration(s.latencies[len(s.latencies)*9/10]))
	if len(s.latencies) > 20 {
		fmt.Printf("Latency 95%%ile: %v\n", time.Duration(s.latencies[len(s.latencies)*19/20]))
	}
	if len(s.latencies) > 100 {
		fmt.Printf("Latency 99%%ile: %v\n", time.Duration(s.latencies[len(s.latencies)*99/100]))
	}
}
