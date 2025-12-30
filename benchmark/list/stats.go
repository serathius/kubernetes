package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type stats struct {
	mu               sync.Mutex
	responseLatency  histogram
	headersLatency   histogram
	readLatency      histogram
	decodeLatency    histogram
	writtenSize      int64
	decompressedSize int64
}

func (s *stats) RecordResponse(latency time.Duration, written, decompressed int64) {
	s.mu.Lock()
	s.responseLatency.Record(latency)
	s.writtenSize += written
	s.decompressedSize += decompressed
	s.mu.Unlock()
}

func (s *stats) RecordReadingBody(latency time.Duration) {
	s.mu.Lock()
	s.readLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) RecordDecodingBody(latency time.Duration) {
	s.mu.Lock()
	s.decodeLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) RecordReadingHeaders(latency time.Duration) {
	s.mu.Lock()
	s.headersLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) printStats(testDuration time.Duration) {
	fmt.Printf("QPS: %.2f\n", float64(s.responseLatency.Len())/testDuration.Seconds())
	if s.responseLatency.Len() == 0 {
		return
	}
	fmt.Printf("Request Count: %v\n", s.responseLatency.Len())
	fmt.Printf("Written Size Average: %v B\n", s.writtenSize/int64(s.responseLatency.Len()))
	fmt.Printf("Decompressed Size Average: %v B\n", s.decompressedSize/int64(s.responseLatency.Len()))
	fmt.Printf("Compression Ratio: %.2f\n", float64(s.decompressedSize)/float64(s.writtenSize))
	fmt.Printf("Throughput: %.2f MB/s\n", float64(s.decompressedSize)/1000/1000/s.responseLatency.Sum().Seconds())
	fmt.Printf("Request Latency Average: %.3f seconds\n", s.responseLatency.Average().Seconds())
	if s.headersLatency.Len() > 0 {
		fmt.Printf("- Headers: %.3f seconds\n", s.headersLatency.Average().Seconds())
	}
	if s.readLatency.Len() > 0 {
		fmt.Printf("- Read: %.3f seconds\n", s.readLatency.Average().Seconds())
	}
	if s.decodeLatency.Len() > 0 {
		fmt.Printf("- Decode: %.3f seconds\n", s.decodeLatency.Average().Seconds())
	}
}

type histogram struct {
	locked   bool
	elements []time.Duration
	sum      time.Duration
}

func (h *histogram) Len() int {
	return len(h.elements)
}

func (h *histogram) Record(latency time.Duration) {
	if h.locked {
		panic("cannot record after locking")
	}
	h.sum += latency
	h.elements = append(h.elements, latency)
}

func (h *histogram) Average() time.Duration {
	return h.sum / time.Duration(len(h.elements))
}

func (h *histogram) Sum() time.Duration {
	return h.sum
}

func (h *histogram) Max() (time.Duration, error) {
	h.sortIfNeeded()
	if len(h.elements) == 0 {
		return 0, fmt.Errorf("no latencies recorded")
	}
	return h.elements[len(h.elements)-1], nil
}

func (h *histogram) P50() time.Duration {
	h.sortIfNeeded()
	if len(h.elements) < 3 {
		panic("not enough latencies recorded")
	}
	if len(h.elements) % 2 == 1 {
		return h.elements[len(h.elements)/2]
	} else {
		return (h.elements[len(h.elements)/2] + h.elements[len(h.elements)/2-1])/2
	}
}

func (h *histogram) P90() time.Duration {
	h.sortIfNeeded()
	if len(h.elements) < 10 {
		panic("not enough latencies recorded")
	}
	if len(h.elements) % 2 == 1 {
		return h.elements[len(h.elements)*9/10]
	} else {
		return (h.elements[len(h.elements)*9/10] + h.elements[len(h.elements)*9/10-1])/2
	}
}

func (h *histogram) P99() time.Duration {
	h.sortIfNeeded()
	if len(h.elements) < 100 {
		panic("not enough latencies recorded")
	}
	if len(h.elements) % 2 == 1 {
		return h.elements[len(h.elements)*99/100]
	} else {
		return (h.elements[len(h.elements)*99/100] + h.elements[len(h.elements)*99/100-1])/2
	}
}

func (h *histogram) sortIfNeeded() {
	if !h.locked {
		h.locked = true
		sort.Slice(h.elements, func(i, j int) bool {
			return h.elements[i] < h.elements[j]
		})
	}
}