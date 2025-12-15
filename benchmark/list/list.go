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

func list(clients []*http.Client, pathTemplate string, config *rest.Config, qps float32, serverURL *url.URL, params string, namespaces int, acceptEncoding string) {
	var wg sync.WaitGroup
	takeN := int(math.Ceil(float64(qps) / 500))
	rateLimiter := rate.NewLimiter(rate.Limit(qps), takeN)
	var mu sync.Mutex
	latencies := []int64{}
	var latencySum int64
	var sizeSum int64
	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(testDuration))
	defer cancel()
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
				path := fmt.Sprintf(pathTemplate, i%namespaces)
				if params != "" {
					path = fmt.Sprintf("%s?%s", path, params)
				}

				url, err := url.Parse(path)
				if err != nil {
					panic(err)
				}
				url.Host = serverURL.Host
				url.Scheme = serverURL.Scheme
				reqCtx, cancel := context.WithTimeout(context.Background(), requestTimeout)
				defer cancel()
				req, err := http.NewRequestWithContext(reqCtx, "GET", url.String(), nil)
				if err != nil {
					panic(fmt.Sprintf("Got error creating a request: %v\n", err))
				}
				req.Header.Set("Accept", config.ContentType)
				req.Header.Set("Accept-Encoding", acceptEncoding)
				start := time.Now()
				resp, err := clients[i%len(clients)].Do(req)
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
				if resp.Header.Get("Content-Type") != config.ContentType || (strings.HasSuffix(config.ContentType, "gzip") && resp.Header.Get("Content-Encoding") != "gzip") {
					panic(fmt.Sprintf("Got bad content type: %q, expected %q\n", resp.Header.Get("Content-Type"), config.ContentType))
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
				mu.Lock()
				latencySum += int64(latency)
				latencies = append(latencies, int64(latency))
				sizeSum += written
				mu.Unlock()
			}(index)
			index++
		}
	}
	wg.Wait()
	fmt.Printf("QPS: %.2f\n", float64(len(latencies))/testDuration.Seconds())
	if len(latencies) == 0 {
		return
	}
	fmt.Printf("Request Count: %v\n", len(latencies))
	fmt.Printf("Size Average: %v\n", sizeSum/int64(len(latencies)))
	fmt.Printf("Latency Average: %v\n", time.Duration(latencySum/int64(len(latencies))))
	slice.SortInts64(latencies)
	fmt.Printf("Latency 50%%ile: %v\n", time.Duration(latencies[len(latencies)/2]))
	fmt.Printf("Latency 90%%ile: %v\n", time.Duration(latencies[len(latencies)*9/10]))
	if len(latencies) > 20 {
		fmt.Printf("Latency 95%%ile: %v\n", time.Duration(latencies[len(latencies)*19/20]))
	}
	if len(latencies) > 100 {
		fmt.Printf("Latency 99%%ile: %v\n", time.Duration(latencies[len(latencies)*99/100]))
	}
}
