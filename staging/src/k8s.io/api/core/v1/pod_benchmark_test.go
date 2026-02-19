package v1

import (
	"os"
	"runtime"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/util/intern"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func BenchmarkPodDecode(b *testing.B) {
	// Load Pod
	wd, err := os.Getwd()
	if err != nil {
		b.Fatalf("Failed to get working directory: %v", err)
	}
	podPath := "/testdata/pod.yaml"
	data, err := os.ReadFile(wd + podPath)
	if err != nil {
		b.Fatalf("Failed to read pod yaml: %v", err)
	}

	var pod Pod
	if err := yaml.Unmarshal(data, &pod); err != nil {
		b.Fatalf("Failed to unmarshal yaml: %v", err)
	}

	protoData, err := pod.Marshal()
	if err != nil {
		b.Fatalf("Failed to marshal pod: %v", err)
	}

	scheme := kruntime.NewScheme()
	AddToScheme(scheme)
	codec := protobuf.NewRawSerializer(scheme, scheme)

	intern.SetInternObjectStrings(b, false)
	intern.SetInternString(b, false)
	metav1.SetInternFieldsV1(b, false)

	b.Run("Intern=False", func(b *testing.B) {
		benchmarkPodDecode(b, codec.Decode, protoData)
	})
	b.Run("Intern=ObjectStrings", func(b *testing.B) {
		intern.SetInternObjectStrings(b, true)
		benchmarkPodDecode(b, codec.Decode, protoData)
	})
	b.Run("Intern=String", func(b *testing.B) {
		intern.SetInternString(b, true)
		benchmarkPodDecode(b, codec.Decode, protoData)
	})
	b.Run("Intern=ManagedFields", func(b *testing.B) {
		metav1.SetInternFieldsV1(b, true)
		benchmarkPodDecode(b, codec.Decode, protoData)
	})
	b.Run("Intern=String,ManagedFields", func(b *testing.B) {
		intern.SetInternString(b, true)
		metav1.SetInternFieldsV1(b, true)
		benchmarkPodDecode(b, codec.Decode, protoData)
	})
}

type DecodeFunc func(data []byte, defaults *schema.GroupVersionKind, into kruntime.Object) (kruntime.Object, *schema.GroupVersionKind, error)

func benchmarkPodDecode(b *testing.B, decode DecodeFunc, protoData []byte) {
	pods := make([]*Pod, b.N)
	for i := range pods {
		pods[i] = &Pod{}
	}

	// Measure memory before
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := decode(protoData, nil, pods[i])
		if err != nil {
			b.Fatalf("Failed to decode: %v", err)
		}
	}
	b.StopTimer()

	// Measure memory after
	runtime.GC()
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	retained := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	b.ReportMetric(float64(retained)/float64(b.N), "retained_B/op")

	runtime.KeepAlive(pods)
}
