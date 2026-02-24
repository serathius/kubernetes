package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/util/uuid"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = corev1.AddToScheme(scheme)
	_ = metav1.AddMetaToScheme(scheme)
}

// --- 1. DATA GENERATION ---

func loadPods(n int) []metav1.WatchEvent {
	dir := "../staging/src/k8s.io/api/core/v1/testdata/"
	files, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}

	var pods []*corev1.Pod
	decoder := json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{Yaml: true, Strict: false})

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			panic(err)
		}

		obj, _, err := decoder.Decode(data, nil, nil)
		if err != nil {
			panic(fmt.Errorf("failed to decode %s: %v", file.Name(), err))
		}
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			panic(fmt.Errorf("expected Pod, got %T in %s", obj, file.Name()))
		}
		pods = append(pods, pod)
	}

	if len(pods) == 0 {
		panic("no pods found in testdata")
	}

	events := make([]metav1.WatchEvent, n)
	startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.Local)
	for i := 0; i < n; i++ {
		pod := *pods[i%len(pods)]
		pod.Name = fmt.Sprintf("%s-%d", pod.Name, i)
		pod.UID = uuid.NewUUID()
		rv, _ := strconv.ParseInt(pod.ResourceVersion, 10, 64)
		pod.ResourceVersion = fmt.Sprintf("%d", rv+int64(i))
		pod.CreationTimestamp = metav1.NewTime(startTime.Add(time.Duration(i) * time.Second))
		pod.Spec.NodeName = fmt.Sprintf("node-%d", i)

		events[i] = metav1.WatchEvent{
			Type:   "ADDED",
			Object: runtime.RawExtension{Object: &pod},
		}
	}
	return events
}

// --- 2. SERIALIZATION ---

func serializeEvents(events []metav1.WatchEvent, s runtime.Serializer, format string) ([][]byte, int) {
	rawEvents := make([][]byte, len(events))
	totalSize := 0
	for i, e := range events {
		// Fix for Protobuf: manually encode the object if it's not already raw
		// We need to copy the event because we are modifying it
		eventCopy := e
		if format == "Protobuf" && eventCopy.Object.Object != nil {
			var podBuf bytes.Buffer
			if err := s.Encode(eventCopy.Object.Object, &podBuf); err != nil {
				panic(err)
			}
			eventCopy.Object.Raw = podBuf.Bytes()
			eventCopy.Object.Object = nil
		}

		var b bytes.Buffer
		if err := s.Encode(&eventCopy, &b); err != nil {
			panic(err)
		}
		rawEvents[i] = b.Bytes()
		totalSize += len(rawEvents[i])
	}
	return rawEvents, totalSize
}

// --- 3. COMPRESSION ---

type Config struct {
	Level          int
	BlockSize      int
	Better         bool
}

func getWriter(w io.Writer, algo string, cfg Config) (io.WriteCloser, error) {
	switch algo {
	case "gzip":
		level := cfg.Level
		if level == 0 {
			level = gzip.BestSpeed
		}
		return gzip.NewWriterLevel(w, level)
	case "snappy":
		return snappy.NewBufferedWriter(w), nil
	case "s2", "s2-snappy":
		var opts []s2.WriterOption
		if cfg.Better {
			opts = append(opts, s2.WriterBetterCompression())
		}
		if cfg.BlockSize > 0 {
			opts = append(opts, s2.WriterBlockSize(cfg.BlockSize))
		}
		if algo == "s2-snappy" {
			opts = append(opts, s2.WriterSnappyCompat())
		}
		return s2.NewWriter(w, opts...), nil
	case "lz4":
		lw := lz4.NewWriter(w)
		lw.Header.CompressionLevel = cfg.Level
		if cfg.BlockSize > 0 {
			lw.Header.BlockMaxSize = cfg.BlockSize
		}
		return lw.WithConcurrency(-1), nil
	case "zstd":
		var opts []zstd.EOption
		level := cfg.Level
		if level == 0 {
			level = int(zstd.SpeedFastest)
		}
		opts = append(opts, zstd.WithEncoderLevel(zstd.EncoderLevel(level)))
		if cfg.BlockSize > 0 {
			opts = append(opts, zstd.WithWindowSize(cfg.BlockSize))
		}
		return zstd.NewWriter(w, opts...)
	default:
		return nil, fmt.Errorf("unknown algo: %s", algo)
	}
}

func compressStream(rawEvents [][]byte, algo string, cfg Config) ([]byte, error) {
	var buf bytes.Buffer
	w, err := getWriter(&buf, algo, cfg)
	if err != nil {
		return nil, err
	}

	for _, b := range rawEvents {
		if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
			return nil, err
		}
		if _, err := w.Write(b); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- 4. VALIDATION ---

func getReader(r io.Reader, algo string) (io.Reader, error) {
	switch algo {
	case "gzip":
		return gzip.NewReader(r)
	case "snappy":
		return snappy.NewReader(r), nil
	case "s2":
		return s2.NewReader(r), nil
	case "lz4":
		return lz4.NewReader(r), nil
	case "zstd":
		return zstd.NewReader(r)
	case "s2-snappy":
		return s2.NewReader(r), nil
	default:
		return nil, fmt.Errorf("unknown algo: %s", algo)
	}
}

func verifyStream(data []byte, original []metav1.WatchEvent, s runtime.Serializer, algo string) error {
	r, err := getReader(bytes.NewReader(data), algo)
	if err != nil {
		return err
	}
	if closer, ok := r.(io.Closer); ok {
		defer closer.Close()
	}

	for i := 0; i < len(original); i++ {
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return fmt.Errorf("%s Stream: len read failed at %d: %v", algo, i, err)
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(r, raw); err != nil {
			return err
		}
		var decoded metav1.WatchEvent
		if _, _, err := s.Decode(raw, nil, &decoded); err != nil {
			return err
		}

		obj, _, err := s.Decode(decoded.Object.Raw, nil, nil)
		if err != nil {
			return err
		}
		decoded.Object.Object = obj

		if original[i].Type != decoded.Type {
			return fmt.Errorf("Type mismatch: expected %v, got %v", original[i].Type, decoded.Type)
		}
		if !reflect.DeepEqual(original[i].Object.Object, decoded.Object.Object) {
			return fmt.Errorf("Object mismatch at index %d", i)
		}
	}
	return nil
}

func decompressStream(data []byte, algo string) error {
	r, err := getReader(bytes.NewReader(data), algo)
	if err != nil {
		return err
	}
	if closer, ok := r.(io.Closer); ok {
		defer closer.Close()
	}

	for {
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("%s Stream: len read failed: %v", algo, err)
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(r, raw); err != nil {
			return err
		}
	}
	return nil
}

// --- 5. TESTS & BENCHMARKS ---

var algos = []string{"gzip", "s2", "s2-snappy", "snappy", "zstd", "lz4"}
var serializers = []struct {
	name       string
	serializer runtime.Serializer
}{
	{"JSON", json.NewSerializer(json.DefaultMetaFactory, scheme, scheme, false)},
	{"Protobuf", protobuf.NewSerializer(scheme, scheme)},
	// {"CBOR", cbor.NewSerializer(scheme, scheme)},
}

func TestVerification(t *testing.T) {
	const N = 1

	events := loadPods(N)
	for _, c := range serializers {
		t.Run("Serializer="+c.name, func(t *testing.T) {
			rawEvents, _ := serializeEvents(events, c.serializer, c.name)
			for _, algo := range algos {
				t.Run("Compression="+algo, func(t *testing.T) {
					// Stream
					compressedStream, err := compressStream(rawEvents, algo, Config{})
					if err != nil {
						t.Errorf("compressStream failed: %v", err)
					}
					if err := verifyStream(compressedStream, events, c.serializer, algo); err != nil {
						t.Errorf("verifyStream failed: %v", err)
					}
				})
			}
		})
	}
}

func BenchmarkCompressionWatchList(b *testing.B) {
	const networkThroughput = 1e9 // 1GB/s
	events := loadPods(10_000)

	configs := []struct {
		Algo string
		Label string
		Config Config
	}{
		{Algo: "gzip", Label: "level=1", Config: Config{Level: 1}},	
		{Algo: "s2", Label: "default", Config: Config{Better: false}},
		{Algo: "s2", Label: "better", Config: Config{Better: true}},
		{Algo: "s2", Label: "better,bs=64K", Config: Config{Better: true, BlockSize: 64 << 10}},
		{Algo: "s2", Label: "better,bs=4M", Config: Config{Better: true, BlockSize: 4 << 20}},
		{Algo: "s2-snappy", Label: "default", Config: Config{}},
		{Algo: "s2-snappy", Label: "better", Config: Config{Better: true}},
		{Algo: "s2-snappy", Label: "better,bs=64K", Config: Config{Better: true, BlockSize: 64 << 10}},
		{Algo: "s2-snappy", Label: "better,bs=4M", Config: Config{Better: true, BlockSize: 4 << 20}},
		{Algo: "snappy", Label: "default", Config: Config{}},
		{Algo: "zstd", Label: "fastest", Config: Config{Level: int(zstd.SpeedFastest)}},
		{Algo: "zstd", Label: "fastest,bs=64K", Config: Config{Level: int(zstd.SpeedFastest), BlockSize: 64 << 10}},
		{Algo: "zstd", Label: "fastest,bs=4M", Config: Config{Level: int(zstd.SpeedFastest), BlockSize: 4 << 20}},
		{Algo: "zstd", Label: "default", Config: Config{Level: int(zstd.SpeedDefault)}},
		{Algo: "lz4", Label: "fastest", Config: Config{Level: 0}},
		{Algo: "lz4", Label: "fastest,bs=64K", Config: Config{Level: 0, BlockSize: 64 << 10}},
		{Algo: "lz4", Label: "fastest,bs=4M", Config: Config{Level: 0, BlockSize: 4 << 20}},
	}

	for _, c := range serializers {
		b.Run("Serializer="+c.name, func(b *testing.B) {
			rawEvents, bytesIn := serializeEvents(events, c.serializer, c.name)
			for _, cfg := range configs {
				b.Run("Algorithm="+cfg.Algo+"/Config="+cfg.Label, func(b *testing.B) {
					var compressionTime, decompressionTime time.Duration 
					var bytesOut int64

					for b.Loop() {
						startC := time.Now()
						compressed, err := compressStream(rawEvents, cfg.Algo, cfg.Config)
						if err != nil {
							b.Errorf("compressStream failed: %v", err)
						}
						compressionTime += time.Since(startC)
						bytesOut += int64(len(compressed))

						startD := time.Now()
						if err := decompressStream(compressed, cfg.Algo); err != nil {
							b.Errorf("decompressStream failed: %v", err)
						}
						decompressionTime += time.Since(startD)
					}
					compressionTime /= time.Duration(b.N)
					decompressionTime /= time.Duration(b.N)
					bytesOut /= int64(b.N)

					throughput := float64(bytesIn) / (networkThroughput*compressionTime.Seconds() + float64(bytesOut) + networkThroughput*decompressionTime.Seconds())
					b.ReportMetric(compressionTime.Seconds(), "compression-seconds/op")
					b.ReportMetric(decompressionTime.Seconds(), "decompression-seconds/op")
					b.ReportMetric(throughput, "throughput-GB/s")
					b.ReportMetric(float64(bytesIn)/float64(bytesOut), "compression-ratio")
					b.ReportAllocs()
				})
			}
		})
	}
}
