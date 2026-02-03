package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/klauspost/compress/s2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = corev1.AddToScheme(scheme)
	_ = metav1.AddMetaToScheme(scheme)
}

// --- 1. DATA GENERATION ---

func generatePods(n int, size string) []metav1.WatchEvent {
	events := make([]metav1.WatchEvent, n)

	for i := 0; i < n; i++ {
		pod := &corev1.Pod{
			TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%d", i),
				Namespace: "default",
				Labels: map[string]string{
					"app":                          "nginx",
					"app.kubernetes.io/name":       "nginx-ingress",
					"app.kubernetes.io/instance":   "nginx-ingress-1.2.3",
					"app.kubernetes.io/version":    "1.2.3",
					"app.kubernetes.io/component":  "controller",
					"app.kubernetes.io/part-of":    "ingress-stack",
					"app.kubernetes.io/managed-by": "helm",
					"helm.sh/chart":                "nginx-ingress-4.0.1",
					"controller-uid":               "a1b2c3d4-e5f6-7890-1234-567890abcdef",
					"pod-template-hash":            "5c6d7e8f90",
				},
				Annotations: map[string]string{
					"prometheus.io/scrape":                           "true",
					"prometheus.io/port":                             "9090",
					"prometheus.io/path":                             "/metrics",
					"sidecar.istio.io/status":                        `{"version":"1.12.1","initContainers":["istio-init"],"containers":["istio-proxy"],"volumes":["istio-envoy","istio-data","istio-podinfo","istio-token","istiod-ca-cert"],"imagePullSecrets":null}`,
					"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
					"k8s.v1.cni.cncf.io/network-status":              `[{"name":"cni-conf","interface":"eth0","ips":["10.244.0.1"],"mac":"0a:58:0a:f4:00:01","dns":{}}]`,
					"vault.hashicorp.com/agent-inject":               "true",
					"vault.hashicorp.com/role":                       "app-role",
					"linkerd.io/inject":                              "enabled",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "nginx",
					Image: "nginx:latest",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
					},
				}},
			},
		}

		var containerCount int
		switch size {
		case "1KB":
			containerCount = 0
			// Trim metadata for 1KB to get closer to 1024
			// Removing sidecar status (~210 bytes) and linkerd inject (~25 bytes)
			// Base ~1275 - 235 = ~1040 bytes
			delete(pod.Annotations, "sidecar.istio.io/status")
			delete(pod.Annotations, "linkerd.io/inject")
		case "10KB":
			containerCount = 11 // ~825 bytes * 11 + base = ~10350
		case "100KB":
			containerCount = 120 // ~825 bytes * 120 + base = ~100275
		}

		for j := 0; j < containerCount; j++ {
			pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
				Name:  fmt.Sprintf("app-container-%d", j),
				Image: "registry.example.com/my-org/my-heavy-app:v1.2.3-release-candidate-20230101",
				Env: []corev1.EnvVar{
					{Name: "JAVA_OPTS", Value: "-Xms1G -Xmx4G -XX:+UseG1GC -Djava.security.egd=file:/dev/./urandom -Dspring.profiles.active=production -Dserver.port=8080 -Dmanagement.endpoints.web.exposure.include=*"},
					{Name: "DB_CONNECTION_STRING", Value: "jdbc:postgresql://db-primary.production.svc.cluster.local:5432/customer_db?sslmode=verify-full&connectTimeout=10&socketTimeout=30&poolSize=50"},
					{Name: "FEATURE_FLAGS", Value: "enable-new-ui,disable-legacy-api,enable-audit-logging,enable-performance-tracing,enable-debug-mode-for-admin"},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "config-vol", MountPath: "/etc/config"},
					{Name: "secret-vol", MountPath: "/etc/secrets"},
					{Name: "data-vol", MountPath: "/var/lib/data"},
				},
			})
		}

		events[i] = metav1.WatchEvent{
			Type:   "ADDED",
			Object: runtime.RawExtension{Object: pod},
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

func getWriter(w io.Writer, algo string) (WriterCloserResetter, error) {
	switch algo {
	case "gzip-1":
		return gzip.NewWriterLevel(w, 1)
	case "gzip-9":
		return gzip.NewWriterLevel(w, gzip.BestCompression)
	case "snappy":
		return s2.NewWriter(w, s2.WriterSnappyCompat()), nil
	case "s2":
		return s2.NewWriter(w), nil
	default:
		return nil, fmt.Errorf("unknown algo: %s", algo)
	}
}

type WriterCloserResetter interface {
	io.WriteCloser
	Reset(writer io.Writer)
}

func compressStream(events [][]byte, algo string, out io.Writer) error {
	w, err := getWriter(out, algo)
	if err != nil {
		return err
	}

	for _, b := range events {
		binary.Write(w, binary.BigEndian, uint32(len(b)))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
	}
	return w.Close()
}

func compressBlock(events [][]byte, algo string, out io.Writer) error {
	var tmp bytes.Buffer
	w, err := getWriter(out, algo)
	if err != nil {
		return err
	}
	for _, b := range events {
		w.Reset(&tmp)
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		err = w.Close()
		if err != nil {
			return err
		}
		err = binary.Write(out, binary.BigEndian, uint32(len(tmp.Bytes())))
		if err != nil {
			return err
		}
		_, err = out.Write(tmp.Bytes())
		if err != nil {
			return err
		}
		tmp.Reset()
	}
	return nil
}

// --- 4. VALIDATION ---

func getReader(r io.Reader, algo string) (io.Reader, error) {
	if strings.HasPrefix(algo, "gzip") {
		return gzip.NewReader(r)
	}
	return s2.NewReader(r), nil
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

func verifyBlocks(data []byte, original []metav1.WatchEvent, s runtime.Serializer, algo string) error {
	reader := bytes.NewReader(data)
	for i := 0; i < len(original); i++ {
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return err
		}
		comp := make([]byte, length)
		io.ReadFull(reader, comp)

		var raw []byte
		r, err := getReader(bytes.NewReader(comp), algo)
		if err != nil {
			return err
		}
		raw, err = io.ReadAll(r)
		if err != nil {
			return err
		}
		if closer, ok := r.(io.Closer); ok {
			closer.Close()
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

// --- 5. TESTS & BENCHMARKS ---

func TestVerification(t *testing.T) {
	const N = 1
	sizes := []string{"1KB", "10KB", "100KB"}
	serializers := []struct {
		name       string
		serializer runtime.Serializer
	}{
		{"JSON", json.NewSerializer(json.DefaultMetaFactory, scheme, scheme, false)},
		{"Protobuf", protobuf.NewSerializer(scheme, scheme)},
	}

	for _, size := range sizes {
		t.Run("Size="+size, func(t *testing.T) {
			events := generatePods(N, size)
			for _, c := range serializers {
				t.Run("Serializer="+string(c.serializer.Identifier()), func(t *testing.T) {
					rawEvents, _ := serializeEvents(events, c.serializer, c.name)
					for _, algo := range []string{"gzip-1", "gzip-9", "snappy", "s2"} {
						t.Run("Compression="+algo, func(t *testing.T) {
							t.Run("Stream", func(t *testing.T) {
								var out bytes.Buffer
								if err := compressStream(rawEvents, algo, &out); err != nil {
									t.Errorf("compressStream failed: %v", err)
								}
							if err := verifyStream(out.Bytes(), events, c.serializer, algo); err != nil {
								t.Errorf("verifyStream failed: %v", err)
							}
							})
							t.Run("Block", func(t *testing.T) {
								var out bytes.Buffer
								if err := compressBlock(rawEvents, algo, &out); err != nil {
									t.Errorf("compressBlock failed: %v", err)
								}
								if err := verifyBlocks(out.Bytes(), events, c.serializer, algo); err != nil {
									t.Errorf("verifyBlocks failed: %v", err)
								}
							})
						})
					}
				})
			}
		})
	}
}

func TestGeneratePodsSize(t *testing.T) {
	sizes := map[string]int{
		"1KB":   1024,
		"10KB":  10240,
		"100KB": 102400,
	}
	// Tolerance 5%
	tolerance := 0.05

	s := json.NewSerializer(json.DefaultMetaFactory, scheme, scheme, false)

	for size, target := range sizes {
		t.Run("Size="+size, func(t *testing.T) {
			events := generatePods(1, size)
			if len(events) != 1 {
				t.Fatalf("expected 1 event, got %d", len(events))
			}
			var buf bytes.Buffer
			if err := s.Encode(events[0].Object.Object, &buf); err != nil {
				t.Fatalf("failed to encode: %v", err)
			}
			size := buf.Len()
			diff := float64(size - target)
			pct := diff / float64(target)

			t.Logf("Target: %d, Actual: %d, Diff: %.2f%%", target, size, pct*100)

			if pct > tolerance || pct < -tolerance {
				t.Errorf("size %d is not within 15%% of target %d (diff: %.2f%%)", size, target, pct*100)
			}
		})
	}
}

func BenchmarkCompression(b *testing.B) {
	const N = 50
	cases := []struct {
		name       string
		serializer runtime.Serializer
	}{
		{"JSON", json.NewSerializer(json.DefaultMetaFactory, scheme, scheme, false)},
		{"Protobuf", protobuf.NewSerializer(scheme, scheme)},
	}

	for _, size := range []string{"1KB", "10KB", "100KB"} {
		b.Run("Size="+size, func(b *testing.B) {
			events := generatePods(N, size)
			for _, c := range cases {
				b.Run("Serializer="+c.name, func(b *testing.B) {
					rawEvents, bytesIn := serializeEvents(events, c.serializer, c.name)
					for _, algo := range []string{"gzip-1", "gzip-9", "snappy", "s2"} {
						b.Run("Compression="+algo, func(b *testing.B) {
							b.Run("Type=Stream", func(b *testing.B) {
								for b.Loop() {
									var out bytes.Buffer
									if err := compressStream(rawEvents, algo, &out); err != nil {
										b.Errorf("compressStream failed: %v", err)
									}
									b.ReportMetric(float64(bytesIn)/float64(len(out.Bytes())), "ratio")
								}
							})
							b.Run("Type=Block", func(b *testing.B) {
								for b.Loop() {
									var out bytes.Buffer
									if err := compressBlock(rawEvents, algo, &out); err != nil {
										b.Errorf("compressBlock failed: %v", err)
									}
									b.ReportMetric(float64(bytesIn)/float64(len(out.Bytes())), "ratio")
								}
							})
						})
					}
				})
			}
		})
	}
}
