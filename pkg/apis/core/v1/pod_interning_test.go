package v1_test

import (
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	v1 "k8s.io/kubernetes/pkg/apis/core/v1"
)

func TestInternPodSpec_Race(t *testing.T) {

	// We need to find the testdata relative to where we run the test
	// Assuming running from pkg/apis/core/v1, we need to go to staging/src/k8s.io/api/core/v1/testdata/pod.yaml
	// Or we can just embed the pod yaml string here to be safe and self-contained.
	// But let's try to read it if possible, or just use a minimal pod that triggers the default.

	podYaml := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: c1
    image: nginx
    resources:
      limits:
        cpu: "1"
      requests:
        memory: "1Gi"
`

	var pod corev1.Pod
	if err := yaml.Unmarshal([]byte(podYaml), &pod); err != nil {
		t.Fatalf("Failed to unmarshal yaml: %v", err)
	}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	codecs := serializer.NewCodecFactory(scheme)

	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), "application/vnd.kubernetes.protobuf")
	if !ok {
		t.Fatal("Protobuf serializer not registered in CodecFactory")
	}

	// 3. Create the Encoder/Decoder for v1
	gv := corev1.SchemeGroupVersion
	// internal := runtime.InternalGroupVersioner
	encoder := codecs.EncoderForVersion(info.Serializer, gv)
	decoder := codecs.DecoderToVersion(info.Serializer, gv)

	protoData, err := runtime.Encode(encoder, &pod)
	if err != nil {
		t.Fatalf("Failed to marshal pod: %v", err)
	}

	// Enable interning
	corev1.SetInternPodSpec(t, true)

	var wg sync.WaitGroup
	concurrency := 100
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()

			// Marshal repeatedly
			for j := 0; j < 10000; j++ {
				// Simulate defaulting on a fresh object (which shares interned maps)
				_, err := runtime.DecodeIntern(decoder, protoData)
				if err != nil {
					t.Errorf("Failed to decode: %v", err)
				}
				// Use the ORIGINAL Defaulter code
				v1.SetDefaults_Pod(p.(*corev1.Pod))
			}
		}(i)
	}
	wg.Wait()
}
