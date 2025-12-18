package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type stats struct {
	mu               sync.Mutex
	latencies        []time.Duration
	latencySum       time.Duration
	writtenSize      int64
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
	fmt.Printf("Latency Average: %.3f seconds\n", s.latencySum.Seconds()/float64(len(s.latencies)))
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
