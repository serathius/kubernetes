package v1

import (
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var (
	podSpecStats = &statsCollector{
		uniqueStrings:    make(map[string]struct{}),
		uniqueStringPtrs: make(map[uintptr]struct{}),
		frameCounts:      make(map[string]int),
		dupStrings:       make(map[string]*stringStats),
	}
	statsStarted sync.Once
)

type stringStats struct {
	Count   int
	Sources map[string]int
}

type statsCollector struct {
	mu               sync.Mutex
	uniqueStrings    map[string]struct{}
	uniqueStringPtrs map[uintptr]struct{}
	frameCounts      map[string]int
	dupStrings       map[string]*stringStats
	totalPodSpecs    int64
	totalBytes       int64
	totalStringBytes int64
	totalStrings     int64
}

func RecordPodSpecStats(spec *PodSpec, data []byte) {
	statsStarted.Do(func() {
		go podSpecStats.reportLoop()
	})

	if spec == nil {
		return
	}

	// Capture stack frames
	rpc := make([]uintptr, 64)
	n := runtime.Callers(2, rpc)
	frames := runtime.CallersFrames(rpc[:n])

	// Collect frames for this call
	currentFrames := make([]string, 0, n)
	for {
		frame, more := frames.Next()
		if !strings.Contains(frame.Function, "runtime.") && !strings.Contains(frame.Function, "RecordPodSpecStats") && !strings.Contains(frame.Function, "Unmarshal") {
			currentFrames = append(currentFrames, frame.Function)
		}
		if !more {
			break
		}
	}

	// Walk strings
	var stringBytes int64
	var stringCount int64
	uniqueStrs := make(map[string]struct{})
	localPtrToPath := make(map[uintptr]string)
	localPtrToString := make(map[uintptr]string)

	walkStrings(reflect.ValueOf(spec), "Spec", func(s string, path string) {
		stringBytes += int64(len(s))
		stringCount++
		uniqueStrs[s] = struct{}{}
		ptr := getStringDataPtr(s)
		localPtrToString[ptr] = s
		if _, ok := localPtrToPath[ptr]; !ok {
			localPtrToPath[ptr] = path
		}
	})

	podSpecStats.mu.Lock()
	defer podSpecStats.mu.Unlock()

	podSpecStats.totalPodSpecs++
	podSpecStats.totalBytes += int64(len(data))
	podSpecStats.totalStringBytes += stringBytes
	podSpecStats.totalStrings += stringCount

	for _, f := range currentFrames {
		podSpecStats.frameCounts[f]++
	}

	for s := range uniqueStrs {
		podSpecStats.uniqueStrings[s] = struct{}{}
	}

	for p, s := range localPtrToString {
		if _, exists := podSpecStats.uniqueStringPtrs[p]; !exists {
			podSpecStats.uniqueStringPtrs[p] = struct{}{}
			stats, ok := podSpecStats.dupStrings[s]
			if !ok {
				stats = &stringStats{
					Sources: make(map[string]int),
				}
				podSpecStats.dupStrings[s] = stats
			}
			stats.Count++
			stats.Sources[localPtrToPath[p]]++
		}
	}
}

func (s *statsCollector) reportLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.logStats()
	}
}

func (s *statsCollector) logStats() {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("--- PodSpec Stats ---\n")
	fmt.Printf("Total PodSpecs: %d\n", s.totalPodSpecs)
	fmt.Printf("Total Bytes: %d\n", s.totalBytes)
	fmt.Printf("Total Strings: %d\n", s.totalStrings)
	fmt.Printf("Total String Bytes: %d\n", s.totalStringBytes)
	if s.totalPodSpecs > 0 {
		fmt.Printf("Avg PodSpec Size: %d\n", s.totalBytes/s.totalPodSpecs)
		fmt.Printf("Avg String Content Size: %d\n", s.totalStringBytes/s.totalPodSpecs)
		fmt.Printf("Avg Strings per PodSpec: %d\n", s.totalStrings/s.totalPodSpecs)
	}
	fmt.Printf("Unique Strings: %d\n", len(s.uniqueStrings))
	fmt.Printf("Unique String Ptrs: %d\n", len(s.uniqueStringPtrs))
	fmt.Printf("Unique Frames: %d\n", len(s.frameCounts))

	fmt.Printf("Top Duplicated Strings (by ptr count):\n")
	type stringCount struct {
		Value string
		Count int
		Stats *stringStats
	}
	var sortedStrings []stringCount
	for v, stats := range s.dupStrings {
		if stats.Count > 1 {
			sortedStrings = append(sortedStrings, stringCount{Value: v, Count: stats.Count, Stats: stats})
		}
	}
	sort.Slice(sortedStrings, func(i, j int) bool {
		return sortedStrings[i].Count > sortedStrings[j].Count
	})

	for i := 0; i < len(sortedStrings) && i < 20; i++ {
		item := sortedStrings[i]
		fmt.Printf("[%d] %q\n", item.Count, item.Value)
		
		// Sort sources
		type sourceCount struct {
			Path  string
			Count int
		}
		var sortedSources []sourceCount
		for path, count := range item.Stats.Sources {
			sortedSources = append(sortedSources, sourceCount{Path: path, Count: count})
		}
		sort.Slice(sortedSources, func(i, j int) bool {
			return sortedSources[i].Count > sortedSources[j].Count
		})
		
		for j := 0; j < len(sortedSources) && j < 5; j++ {
			fmt.Printf("    - %d: %s\n", sortedSources[j].Count, sortedSources[j].Path)
		}
	}

	fmt.Printf("Top Frames:\n")

	// Sort frames by count
	type frameCount struct {
		Name  string
		Count int
	}
	var sortedFrames []frameCount
	for f, c := range s.frameCounts {
		sortedFrames = append(sortedFrames, frameCount{Name: f, Count: c})
	}
	// Sort descending
	sort.Slice(sortedFrames, func(i, j int) bool {
		return sortedFrames[i].Count > sortedFrames[j].Count
	})

	// Print top 50
	for i := 0; i < len(sortedFrames) && i < 50; i++ {
		fmt.Printf("[%d] %s\n", sortedFrames[i].Count, sortedFrames[i].Name)
	}
	fmt.Printf("---------------------\n")
}

func walkStrings(v reflect.Value, path string, fn func(string, string)) {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.String:
		fn(v.String(), path)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			fieldName := t.Field(i).Name
			walkStrings(v.Field(i), path+"."+fieldName, fn)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStrings(v.Index(i), fmt.Sprintf("%s[%d]", path, i), fn)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			walkStrings(iter.Key(), path+".<key>", fn)
			walkStrings(iter.Value(), path+".<value>", fn)
		}
	}
}

func getStringDataPtr(s string) uintptr {
	return uintptr(unsafe.Pointer(unsafe.StringData(s)))
}
