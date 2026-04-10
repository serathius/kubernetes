package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type stats struct {
	mu                     sync.Mutex
	requestLatency         histogram
	headersLatency         histogram
	readingResponseLatency histogram
	decompressLatency      histogram
	bufferingLatency       histogram
	decodeLatency          histogram
	writtenSize            int64
	decompressedSize       int64
}

func (s *stats) RecordReadingHeaders(latency time.Duration) {
	s.mu.Lock()
	s.headersLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) RecordReadingResponse(latency time.Duration, bytes int64) {
	s.mu.Lock()
	s.readingResponseLatency.Record(latency)
	s.writtenSize += bytes
	s.mu.Unlock()
}

func (s *stats) RecordDecompressing(latency time.Duration, bytes int64) {
	s.mu.Lock()
	s.decompressLatency.Record(latency)
	s.decompressedSize += bytes
	s.mu.Unlock()
}

func (s *stats) RecordBuffering(latency time.Duration) {
	s.mu.Lock()
	s.bufferingLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) RecordDecodingBody(latency time.Duration) {
	s.mu.Lock()
	s.decodeLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) RecordRequestLatency(latency time.Duration) {
	s.mu.Lock()
	s.requestLatency.Record(latency)
	s.mu.Unlock()
}

func (s *stats) printStats(testDuration time.Duration) {
	fmt.Printf("QPS: %.2f\n", float64(s.requestLatency.Len())/testDuration.Seconds())
	if s.requestLatency.Len() == 0 {
		return
	}
	fmt.Printf("Request Count: %v\n", s.requestLatency.Len())
	if s.writtenSize != 0 {
		fmt.Printf("Written Size Average: %v B\n", s.writtenSize/int64(s.requestLatency.Len()))
	}
	if s.decompressedSize != 0 {
		fmt.Printf("Decompressed Size Average: %v B\n", s.decompressedSize/int64(s.requestLatency.Len()))
	}
	if s.writtenSize != 0 && s.decompressedSize != 0 {
		fmt.Printf("Compression Ratio: %.2f\n", float64(s.decompressedSize)/float64(s.writtenSize))
	}
	if s.decompressedSize != 0 {
		fmt.Printf("Throughput: %.2f MB/s\n", float64(s.decompressedSize)/1000/1000/s.requestLatency.Sum().Seconds())
	} else if s.writtenSize != 0 {
		fmt.Printf("Throughput: %.2f MB/s\n", float64(s.writtenSize)/1000/1000/s.requestLatency.Sum().Seconds())
	}
	fmt.Printf("Request Latency P50: %.3f seconds\n", s.requestLatency.P50().Seconds())
	fmt.Printf("Request Latency P90: %.3f seconds\n", s.requestLatency.P90().Seconds())
	if s.requestLatency.Len() >= 100 {
		fmt.Printf("Request Latency P99: %.3f seconds\n", s.requestLatency.P99().Seconds())
	}
	fmt.Printf("Request Latency Average: %.3f seconds\n", s.requestLatency.Average().Seconds())
	var averageSum time.Duration
	type averageName struct {
		name      string
		histogram histogram
	}
	for _, latency := range []averageName{{"Headers", s.headersLatency}, {"Reading Response", s.readingResponseLatency}, {"Decompressing", s.decompressLatency}, {"Buffering", s.bufferingLatency}, {"Decoding Body", s.decodeLatency}} {
		if latency.histogram.Len() > 0 {
			fmt.Printf("- %v: %.3f seconds\n", latency.name, latency.histogram.Average().Seconds())
			averageSum += latency.histogram.Average()
		}
	}
	unaccountedLatency := s.requestLatency.Average() - averageSum
	if unaccountedLatency >= time.Millisecond {
		fmt.Printf("WARNING: Error in latency accounting: Unaccounted %.3f seconds\n", unaccountedLatency.Seconds())
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
	if len(h.elements)%2 == 1 {
		return h.elements[len(h.elements)/2]
	} else {
		return (h.elements[len(h.elements)/2] + h.elements[len(h.elements)/2-1]) / 2
	}
}

func (h *histogram) P90() time.Duration {
	h.sortIfNeeded()
	if len(h.elements) < 10 {
		panic("not enough latencies recorded")
	}
	if len(h.elements)%2 == 1 {
		return h.elements[len(h.elements)*9/10]
	} else {
		return (h.elements[len(h.elements)*9/10] + h.elements[len(h.elements)*9/10-1]) / 2
	}
}

func (h *histogram) P99() time.Duration {
	h.sortIfNeeded()
	if len(h.elements) < 100 {
		panic("not enough latencies recorded")
	}
	if len(h.elements)%2 == 1 {
		return h.elements[len(h.elements)*99/100]
	} else {
		return (h.elements[len(h.elements)*99/100] + h.elements[len(h.elements)*99/100-1]) / 2
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
