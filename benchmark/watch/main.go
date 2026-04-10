package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/managedfields/managedfieldstest"
	"k8s.io/client-go/kubernetes"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/kube-openapi/pkg/validation/spec"
)

var (
	objectSize          int
	objectCount         int
	maxQPS              float32
	initResourceVersion string
	resourceType        string
	etcdEndpoint        string
)

func main() {
	flag.IntVar(&objectSize, "object-size", 1000, "size of objects in bytes")
	flag.IntVar(&objectCount, "object-count", 10000, "number of unique objects")
	flag.Float32Var(&maxQPS, "qps", 2000, "max QPS for client")
	flag.StringVar(&initResourceVersion, "init-resource-version", "", "initial resource version for watch")
	flag.StringVar(&resourceType, "resource", "configmap", "resource type: configmap or pod")
	flag.StringVar(&etcdEndpoint, "etcd-endpoint", "https://192.168.8.2:2379", "etcd endpoint")
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		panic(err.Error())
	}
	config.QPS = -1
	config.ContentType = "application/vnd.kubernetes.protobuf"

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	runLatencyMode(clientset)
}

func runLatencyMode(clientset kubernetes.Interface) {
	var wg sync.WaitGroup

	mux := sync.Mutex{}
	writeRVTime := make(map[uint64]time.Time)

	etcdClient, err := newEtcdClient()
	if err != nil {
		panic(err)
	}
	defer etcdClient.Close()

	keys, values := prepareObjects(objectCount, objectSize, resourceType)
	benchmarkDuration := time.Second * 30
	ctx, cancel := context.WithTimeout(context.Background(), benchmarkDuration)
	defer cancel()

	lastRev := make(chan uint64, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		startWriters(ctx, etcdClient, &wg, &mux, writeRVTime, keys, values, lastRev)
	}()

	watchCacheRVTime := make(map[time.Time]uint64)
	ticker := time.NewTicker(time.Millisecond * 10)
	defer ticker.Stop()
	var lastRV uint64
	loop:
	for {
		select {
		case rv := <-lastRev:
			lastRV = rv
		case <-ticker.C:
			ctx := context.Background()
			rv, respTime, err := getWatchCacheRV(ctx, clientset, resourceType)
			if err != nil {
				fmt.Printf("Error getting watch cache RV: %v\n", err)
				continue
			}
			watchCacheRVTime[respTime] = rv
			if lastRV != 0 && rv >= lastRV {
				break loop
			}
			fmt.Printf("RV: %d\n", rv)
		}
	}
	wg.Wait()
	durations := []float64{}
	for t, rv := range watchCacheRVTime {
		delay := t.Sub(writeRVTime[rv])
		if delay > benchmarkDuration {
			continue
		}
		durations = append(durations, delay.Seconds())
	}
	fmt.Printf("Total time: %fs\n", benchmarkDuration.Seconds())
	fmt.Printf("QPS: %f\n", float64(len(writeRVTime))/benchmarkDuration.Seconds())
	fmt.Printf("RV sample rate: %f\n", float64(len(watchCacheRVTime))/benchmarkDuration.Seconds())
	sort.Float64s(durations)
	if len(durations) > 4 {
		fmt.Printf("P50: %f\n", durations[len(durations)/2])
	}
	if len(durations) > 20 {
		fmt.Printf("P90: %f\n", durations[len(durations)*9/10])
	}
	if len(durations) > 101 {
		fmt.Printf("P99: %f\n", durations[len(durations)*99/100])
	}
	if len(durations) > 1001 {
		fmt.Printf("P99.9: %f\n", durations[len(durations)*999/1000])
	}
}


func getWatchCacheRV(ctx context.Context, clientset kubernetes.Interface, resource string) (uint64, time.Time, error) {
	const fakeNamespace = "staleness_probe_fake_namespace!"
	var listResourceVersion string
	var err error

	startTime := time.Now()
	listOpts := metav1.ListOptions{ResourceVersion: "0"}
	switch resource {
	case "configmap":
		var list *v1.ConfigMapList
		list, err = clientset.CoreV1().ConfigMaps(fakeNamespace).List(ctx, listOpts)
		if err == nil {
			listResourceVersion = list.ResourceVersion
		}
	case "pod":
		var list *v1.PodList
		list, err = clientset.CoreV1().Pods(fakeNamespace).List(ctx, listOpts)
		if err == nil {
			listResourceVersion = list.ResourceVersion
		}
	default:
		return 0, time.Time{}, fmt.Errorf("unknown resource %s", resource)
	}
	respTime := time.Now()
	if err != nil {
		return 0, respTime, err
	}

	rv, err := strconv.ParseUint(listResourceVersion, 10, 64)
	if err != nil {
		return 0, respTime, fmt.Errorf("failed to parse RV %q: %v", listResourceVersion, err)
	}

	return rv, startTime.Add(respTime.Sub(startTime)/2), nil
}

func prepareObjects(count int, size int, resType string) ([]string, []string) {
	serializer := createProtobufSerializer()

	// Load OpenAPI spec for realistic managed fields
	data, err := os.ReadFile("api/openapi-spec/swagger.json")
	if err != nil {
		// Try fallback for tests running from package directory
		data, err = os.ReadFile("../../api/openapi-spec/swagger.json")
		if err != nil {
			panic(fmt.Sprintf("Failed to read openapi spec: %v. Please run from repo root.", err))
		}
	}
	var swagger spec.Swagger
	if err := json.Unmarshal(data, &swagger); err != nil {
		panic(fmt.Sprintf("Failed to unmarshal openapi spec: %v", err))
	}
	definitions := map[string]*spec.Schema{}
	for k, v := range swagger.Definitions {
		p := v
		definitions[k] = &p
	}
	typeConverter, err := managedfields.NewTypeConverter(definitions, false)
	if err != nil {
		panic(fmt.Sprintf("Failed to create type converter: %v", err))
	}

	keys := make([]string, count)
	encodedValues := make([]string, count)

	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%d", i)
		var obj runtime.Object
		var key string
		var kind string

		switch resType {
		case "pod":
			obj = generateSpecificPod(name, size, typeConverter)
			key = fmt.Sprintf("/registry/pods/default/%s", name)
			kind = "Pod"
		case "configmap":
			obj = randomConfigmap(name)
			key = fmt.Sprintf("/registry/configmaps/default/%s", name)
			kind = "ConfigMap"
		default:
			panic(fmt.Sprintf("unknown resource %s", resType))
		}

		keys[i] = key

		// Encode to Protobuf
		var data []byte
		var err error
		switch o := obj.(type) {
		case *v1.ConfigMap:
			data, err = o.Marshal()
		case *v1.Pod:
			data, err = o.Marshal()
		}
		if err != nil {
			panic(fmt.Sprintf("failed to marshal object: %v", err))
		}

		unk := &runtime.Unknown{
			TypeMeta: runtime.TypeMeta{
				Kind:       kind,
				APIVersion: "v1",
			},
			Raw: data,
		}

		var buf bytes.Buffer
		err = serializer.Encode(unk, &buf)
		if err != nil {
			panic(fmt.Sprintf("failed to encode unknown: %v", err))
		}

		encodedValues[i] = buf.String()
	}

	return keys, encodedValues
}

func startWriters(ctx context.Context, etcdClient *clientv3.Client, wg *sync.WaitGroup, mux *sync.Mutex, revisionsTime map[uint64]time.Time, keys []string, values []string, lastRevC chan uint64) {
	takeN := int(math.Ceil(float64(maxQPS) / 500))
	rateLimiter := rate.NewLimiter(rate.Limit(maxQPS), takeN)
	index := 0
	lastRV := uint64(0)
	for {
		err := rateLimiter.WaitN(ctx, takeN)
		if err != nil && errors.Is(err, context.DeadlineExceeded) {
			lastRevC <- lastRV
			return
		}
		for j := 0; j < takeN; j++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				key := keys[i%len(keys)]
				val := values[i%len(values)]
				rv, writeTime, err := write(ctx, etcdClient, key, val)
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "would exceed context deadline") {
						return
					}
					if errors.Is(err, rpctypes.ErrGRPCTimeout) || strings.Contains(err.Error(), "etcdserver: too many requests") || strings.Contains(err.Error(), "etcdserver: request timed out") {
						return
					}
					panic(err)
				}
				mux.Lock()
				revisionsTime[rv] = writeTime
				lastRV = max(rv, lastRV)
				mux.Unlock()
			}(index)
			index++
		}
	}
}

func write(ctx context.Context, etcdClient *clientv3.Client, key string, val string) (uint64, time.Time, error) {
	startTime := time.Now()
	resp, err := etcdClient.KV.Put(ctx, key, val)
	respTime := time.Now()
	if err != nil {
		return 0, time.Time{}, err
	}
	return uint64(resp.Header.Revision), startTime.Add(respTime.Sub(startTime)/2), nil
}

func generatePodWithScale(name string, scale float64) *v1.Pod {
	if scale < 0 {
		scale = 0
	}
	if scale > 1 {
		scale = 1
	}

	annotationsCount := 1 + int(math.Round(scale*9))
	labelsCount := 1 + int(math.Round(scale*19))
	initContainersCount := 0 + int(math.Round(scale*2))
	mainContainersCount := 1 + int(math.Round(scale*3))
	envCount := 1 + int(math.Round(scale*19))
	volCount := 1 + int(math.Round(scale*19))

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "default",
			Annotations: make(map[string]string),
			Labels:      make(map[string]string),
		},
		Spec: v1.PodSpec{
			Containers:     make([]v1.Container, mainContainersCount),
			InitContainers: make([]v1.Container, initContainersCount),
		},
	}

	for i := 0; i < annotationsCount; i++ {
		pod.Annotations[fmt.Sprintf("a%d", i)] = ""
	}

	for i := 0; i < labelsCount; i++ {
		pod.Labels[fmt.Sprintf("l%d", i)] = ""
	}

	volCounter := 0
	createContainers := func(containers []v1.Container, prefix string) {
		for i := range containers {
			containers[i] = v1.Container{
				Name:  fmt.Sprintf("%s%d", string(prefix[0]), i),
				Image: "n",
				Env:   make([]v1.EnvVar, envCount),
			}
			for j := 0; j < envCount; j++ {
				containers[i].Env[j] = v1.EnvVar{
					Name:  fmt.Sprintf("E%d", j),
					Value: "",
				}
			}
			for j := 0; j < volCount; j++ {
				volName := fmt.Sprintf("v%d", volCounter)
				volCounter++
				containers[i].VolumeMounts = append(containers[i].VolumeMounts, v1.VolumeMount{
					Name:      volName,
					MountPath: fmt.Sprintf("/m/%s", volName),
				})
				pod.Spec.Volumes = append(pod.Spec.Volumes, v1.Volume{
					Name: volName,
					VolumeSource: v1.VolumeSource{
						EmptyDir: &v1.EmptyDirVolumeSource{},
					},
				})
			}
		}
	}

	createContainers(pod.Spec.InitContainers, "init")
	createContainers(pod.Spec.Containers, "main")

	return pod
}
func generateSpecificPod(name string, targetSize int, typeConverter managedfields.TypeConverter) *v1.Pod {
	cacheMux.Lock()
	scale, ok := optimalScaleCache[targetSize]
	cacheMux.Unlock()

	if !ok {
		scale = 0.0
		if targetSize > 0 {
			for s := 1.0; s >= 0.0; s -= 0.05 {
				testPod := generateSpecificPodInternal("test-scale", s, 0, typeConverter)
				data, _ := testPod.Marshal()
				if len(data) <= targetSize {
					scale = s
					break
				}
			}
		}
		cacheMux.Lock()
		optimalScaleCache[targetSize] = scale
		cacheMux.Unlock()
		fmt.Printf("Selected and cached optimal scale %f for target size %d\n", scale, targetSize)
	}

	return generateSpecificPodInternal(name, scale, targetSize, typeConverter)
}

var (
	optimalScaleCache = make(map[int]float64)
	cacheMux          sync.Mutex
)

func generateSpecificPodInternal(name string, scale float64, targetSize int, typeConverter managedfields.TypeConverter) *v1.Pod {
	var pod *v1.Pod

	pod = generatePodWithScale(name, scale)

	// Populate Status
	fixedTime := metav1.Time{Time: time.Date(2026, 3, 13, 9, 48, 25, 0, time.UTC)}
	pod.Status.Phase = v1.PodRunning
	pod.Status.StartTime = &fixedTime
	pod.Status.Conditions = []v1.PodCondition{
		{Type: v1.PodScheduled, Status: v1.ConditionTrue, LastTransitionTime: fixedTime},
		{Type: v1.PodInitialized, Status: v1.ConditionTrue, LastTransitionTime: fixedTime},
		{Type: v1.PodReady, Status: v1.ConditionTrue, LastTransitionTime: fixedTime},
		{Type: v1.ContainersReady, Status: v1.ConditionTrue, LastTransitionTime: fixedTime},
	}

	for _, c := range pod.Spec.InitContainers {
		pod.Status.InitContainerStatuses = append(pod.Status.InitContainerStatuses, v1.ContainerStatus{
			Name:  c.Name,
			Ready: true,
			State: v1.ContainerState{
				Terminated: &v1.ContainerStateTerminated{
					ExitCode: 0,
					Reason:   "Completed",
					StartedAt: fixedTime,
					FinishedAt: fixedTime,
				},
			},
		})
	}

	for _, c := range pod.Spec.Containers {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, v1.ContainerStatus{
			Name:  c.Name,
			Ready: true,
			State: v1.ContainerState{
				Running: &v1.ContainerStateRunning{
					StartedAt: fixedTime,
				},
			},
		})
	}

	// Generate managedFields using API server code
	f := managedfieldstest.NewTestFieldManager(typeConverter, schema.FromAPIVersionAndKind("v1", "Pod"))
	pod.APIVersion = "v1"
	pod.Kind = "Pod"
	pod.Spec.SchedulerName = "non-existent-scheduler"
	if err := f.Update(pod, "kube-apiserver"); err != nil {
		panic(fmt.Sprintf("failed to update managed fields: %v", err))
	}
	pod = f.Live().(*v1.Pod)

	// Calculate current size via marshal (including managedFields)
	data, _ := pod.Marshal()
	currentSize := len(data)

	if targetSize > currentSize {
		// Distribute extra size among labels, annotations, and env values.
		annotationsCount := 1 + int(math.Round(scale*9))
		labelsCount := 1 + int(math.Round(scale*19))
		initContainersCount := 0 + int(math.Round(scale*2))
		mainContainersCount := 1 + int(math.Round(scale*3))
		envCount := 1 + int(math.Round(scale*19))

		totalItems := annotationsCount + labelsCount + ((initContainersCount + mainContainersCount) * envCount)

		extraSizeNeeded := targetSize - currentSize
		extraPerItem := extraSizeNeeded / totalItems

		if extraPerItem > 0 {
			for k := range pod.Labels {
				pod.Labels[k] += RandString(extraPerItem)
			}
			for k := range pod.Annotations {
				pod.Annotations[k] += RandString(extraPerItem)
			}
			padEnv := func(containers []v1.Container) {
				for i := range containers {
					for j := range containers[i].Env {
						containers[i].Env[j].Value += RandString(extraPerItem)
					}
				}
			}
			padEnv(pod.Spec.InitContainers)
			padEnv(pod.Spec.Containers)
		}
	}

	return pod
}

func randomConfigmap(name string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Immutable: nil,
		Data: map[string]string{
			"random": RandString(objectSize),
		},
		BinaryData: nil,
	}
}

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandString(l int) string {
	s := make([]byte, l)
	for i := 0; i < l; i++ {
		s[i] = chars[rand.Intn(len(chars))]
	}
	return string(s)
}

func newEtcdClient() (*clientv3.Client, error) {
	cfg := clientv3.Config{
		Endpoints:   []string{etcdEndpoint},
		DialTimeout: 5 * time.Second,
		TLS: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return clientv3.New(cfg)
}

func createProtobufSerializer() *protobuf.Serializer {
	return protobuf.NewSerializer(k8sscheme.Scheme, k8sscheme.Scheme)
}
