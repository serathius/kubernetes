package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	flag "github.com/spf13/pflag"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/kubectl/pkg/util/slice"
)

var listers = 100
var testDuration = 20 * time.Second

func main() {
	contentType := flag.String("content-type", "", "json or protobuf")
	resource := flag.String("resource", "", "configmap, pod, or cr")
	rev := flag.String("rv", "", "empty, zero, exact, continue")
	create := flag.Bool("create", false, "")
	qps := flag.Float32("qps", 0, "")
	objectSize := flag.Int("object-size", 0, "")
	objectCount := flag.Int("object-count", 0, "")
	serviceAccount := flag.String("service-account", "", "")
	namespaces := flag.Int("namespaces", 1, "")
	clients := flag.Int("clients", 1, "")
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		fmt.Printf("failed to read kube config: %s\n", err)
		os.Exit(1)
	}
	config.QPS = 1000
	config.Burst = 1
	switch *contentType {
	case "json":
		config.ContentType = "application/json"
	case "protobuf":
		config.ContentType = "application/vnd.kubernetes.protobuf"
	case "cbor":
		config.ContentType = "application/cbor"
	case "yaml":
		config.ContentType = "application/yaml"
	default:
		fmt.Printf("--content-type should be set to \"json\" or \"protobuf\"\n")
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("failed to create client: %s\n", err)
		os.Exit(1)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		fmt.Printf("failed to create dynamic client: %s\n", err)
		os.Exit(1)
	}
	if *create {
		if *objectSize == 0 {
			fmt.Printf("--object-size needs to be set\n")
			os.Exit(1)
		}
		if *objectCount == 0 {
			fmt.Printf("--object-count needs to be set\n")
			os.Exit(1)
		}
		switch *resource {
		case "configmap":
			createConfigmaps(clientset, *objectSize, *objectCount, *namespaces)
		case "secret":
			createSecrets(clientset, *objectSize, *objectCount, *namespaces)
		case "pod":
			createPods(clientset, *objectSize, *objectCount)
		case "cr":
			createCRs(dynamicClient, *objectSize, *objectCount)
		default:
			print("--resource should be set to \"configmap\", \"pod\" or \"cr\"\n")
			os.Exit(1)
		}
		return
	}
	if *qps == 0 {
		fmt.Printf("--qps needs to be set\n")
		os.Exit(1)
	}
	if *clients < 1 {
		fmt.Printf("--clients needs to be at least 1\n")
		os.Exit(1)
	}

	var opts metav1.ListOptions
	resourceVersion := ""
	resourceVersionMatch := ""
	continueToken := ""
	switch *rev {
	case "empty":
	case "zero":
		resourceVersion = "0"
	case "exact":
		resp, err := clientset.CoreV1().ConfigMaps("default").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Unexpected err: %s", err)
			os.Exit(1)
		}
		resourceVersion = resp.ResourceVersion
		resourceVersionMatch = string(metav1.ResourceVersionMatchExact)
	case "continue":
		resp, err := clientset.CoreV1().ConfigMaps("default").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Unexpected err: %s", err)
			os.Exit(1)
		}
		rv, err := strconv.Atoi(resp.ResourceVersion)
		if err != nil {
			fmt.Printf("Unexpected err: %s", err)
			os.Exit(1)
		}
		continueToken, err = storage.EncodeContinue("/\u0000", "/", int64(rv))
		if err != nil {
			fmt.Printf("Unexpected err: %s", err)
			os.Exit(1)
		}
	default:
		fmt.Println(`--rv should be set to "empty", "zero", "exact" or "continue"`)
		os.Exit(1)
	}
	serverURL, _, err := rest.DefaultServerUrlFor(config)
	if err != nil {
		panic(err)
	}
	if *serviceAccount != "" {
		token, err := createToken(clientset, "default", *serviceAccount)
		if err != nil {
			fmt.Printf("failed to create token: %s\n", err)
			os.Exit(1)
		}
		config.BearerToken = token
		config.TLSClientConfig.KeyData = []byte("")
	}

	switch *resource {
	case "configmap", "secret":
		params := []string{}
		if resourceVersion != "" {
			params = append(params, fmt.Sprintf("resourceVersion=%s", resourceVersion))
		}
		if resourceVersionMatch != "" {
			params = append(params, fmt.Sprintf("resourceVersionMatch=%s", resourceVersionMatch))
		}
		if continueToken != "" {
			params = append(params, fmt.Sprintf("continue=%s", continueToken))
		}
		// params = append(params, "pretty=1")
		// params = append(params, "labelSelector=app%3D0")
		// params = append(params, "limit=100")
		paramStr := strings.Join(params, "&")
		httpClients := make([]*http.Client, *clients)
		for i := 0; i < *clients; i++ {
			httpClients[i], err = rest.HTTPClientFor(config)
			if err != nil {
				fmt.Printf("failed to create client: %s\n", err)
				os.Exit(1)
			}
		}
		list(httpClients, *resource+"s", config, *qps, serverURL, paramStr, *namespaces)
	case "pod":
		listPods(clientset, opts)
	case "cr":
		listCRs(dynamicClient, opts)
	default:
		print("--resource should be set to \"configmap\", \"pod\" or \"cr\"\n")
		os.Exit(1)
	}
	fmt.Printf("Done\n")
}

func createToken(clientset kubernetes.Interface, namespace, name string) (string, error) {
	request := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{},
	}
	response, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(context.TODO(), name, request, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return response.Status.Token, nil
}

func createConfigmaps(clientset kubernetes.Interface, objectSize, objectCount, namespaces int) {
	var wg sync.WaitGroup
	for i := 0; i < namespaces; i++ {
		namespace := fmt.Sprintf("%d", i)
		_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), randomNamespace(namespace), metav1.CreateOptions{})
		if err != nil {
			panic(err)
		}
		for j := 0; j < objectCount; j++ {
			name := fmt.Sprintf("%d", j)
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				_, err := clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), randomConfigmap(name, objectSize), metav1.CreateOptions{})
				if err != nil {
					panic(err)
				}
			}(name)
		}
	}
	wg.Wait()
	fmt.Printf("Created configmaps\n")
}

func createSecrets(clientset kubernetes.Interface, objectSize, objectCount, namespaces int) {
	var wg sync.WaitGroup
	for i := 0; i < namespaces; i++ {
		namespace := fmt.Sprintf("%d", i)
		_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), randomNamespace(namespace), metav1.CreateOptions{})
		if err != nil {
			panic(err)
		}
		for j := 0; j < objectCount; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				_, err := clientset.CoreV1().Secrets(namespace).Create(context.TODO(), randomSecret(j, objectSize), metav1.CreateOptions{})
				if err != nil {
					panic(err)
				}
			}(j)
		}
	}
	wg.Wait()
	fmt.Printf("Created secrets\n")
}

func createPods(clientset kubernetes.Interface, objectSize, objectCount int) {
	var wg sync.WaitGroup
	for i := 0; i < objectCount; i++ {
		name := fmt.Sprintf("%d", i)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_, err := clientset.CoreV1().Pods("default").Create(context.TODO(), randomPod(name, objectSize), metav1.CreateOptions{})
			if err != nil {
				panic(err)
			}
		}(name)
	}
	wg.Wait()
	fmt.Printf("Created pods\n")
}

func createCRs(clientset *dynamic.DynamicClient, objectSize, objectCount int) {
	resource := schema.GroupVersionResource{
		Group:    "stable.example.com",
		Version:  "v1",
		Resource: "crontabs",
	}
	var wg sync.WaitGroup
	for i := 0; i < objectCount; i++ {
		name := fmt.Sprintf("%d", i)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_, err := clientset.Resource(resource).Namespace("default").Create(context.TODO(), randomCR(name, objectSize), metav1.CreateOptions{})
			if err != nil {
				panic(err)
			}
		}(name)
	}
	wg.Wait()
	fmt.Printf("Created crs\n")
}

func listCRs(clientset *dynamic.DynamicClient, opts metav1.ListOptions) {
	resource := schema.GroupVersionResource{
		Group:    "stable.example.com",
		Version:  "v1",
		Resource: "crontabs",
	}
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < listers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(start) < testDuration {
				start := time.Now()
				resp, err := clientset.Resource(resource).Namespace("default").List(context.TODO(), opts)
				if err != nil {
					panic(err)
				}
				fmt.Printf("List RVM=%q RV=%q Continue=%q items=%d, duration=%v\n", opts.ResourceVersionMatch, opts.ResourceVersion, opts.Continue, len(resp.Items), time.Since(start))
			}
		}()
	}
	wg.Wait()
}

func list(clients []*http.Client, resource string, config *rest.Config, qps float32, serverURL *url.URL, params string, namespaces int) {
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
				path := fmt.Sprintf("/api/v1/namespaces/%d/%s", i%namespaces, resource)
				if params != "" {
					path = fmt.Sprintf("%s?%s", path, params)
				}

				url, err := url.Parse(path)
				if err != nil {
					panic(err)
				}
				url.Host = serverURL.Host
				url.Scheme = serverURL.Scheme
				reqCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				req, err := http.NewRequestWithContext(reqCtx, "GET", url.String(), nil)
				if err != nil {
					panic(fmt.Sprintf("Got error creating a request: %v\n", err))
				}
				req.Header.Set("Accept", config.ContentType)
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
				if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent {
					panic(fmt.Sprintf("Got bad status code: %v\n", resp.Status))
				}
				if resp.Header.Get("Content-Type") != config.ContentType {
					panic(fmt.Sprintf("Got bad content type: %q, expected %q\n", resp.Header.Get("Content-Type"), config.ContentType))
				}
				written, err := io.Copy(io.Discard, resp.Body)
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

func listPods(clientset kubernetes.Interface, opts metav1.ListOptions) {
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < listers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(start) < testDuration {
				start := time.Now()
				resp, err := clientset.CoreV1().Pods("default").List(context.TODO(), opts)
				if err != nil {
					panic(err)
				}
				fmt.Printf("List RVM=%q RV=%q Continue=%q items=%d, duration=%v size=%v\n", opts.ResourceVersionMatch, opts.ResourceVersion, opts.Continue, len(resp.Items), time.Since(start), resp.Size())
			}
		}()
	}
	wg.Wait()
}

func randomNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func randomConfigmap(name string, objectSize int) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Immutable: nil,
		Data: map[string]string{
			"random": rand.String(objectSize),
		},
		BinaryData: nil,
	}
}

func randomSecret(i int, objectSize int) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%d", i),
			Labels: map[string]string{
				"app": fmt.Sprintf("%d", i%10),
			},
		},
		Immutable: nil,
		StringData: map[string]string{
			"random": rand.String(objectSize),
		},
	}
}

func randomCR(name string, objectSize int) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "stable.example.com/v1",
			"kind":       "CronTab",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "default",
			},
			"value": rand.String(objectSize),
		},
	}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "stable.example.com",
		Version: "v1",
		Kind:    "CronTab",
	})
	return obj
}

func randomPod(name string, objectSize int) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.PodSpec{
			NodeName:      rand.String(253),
			Hostname:      rand.String(63),
			Subdomain:     rand.String(63),
			SchedulerName: rand.String(1000),
		},
		Status: v1.PodStatus{
			Message:           rand.String(1000),
			Reason:            rand.String(1000),
			NominatedNodeName: rand.String(1000),
			HostIP:            rand.String(1000),
			PodIP:             rand.String(1000),
		},
	}
	for pod.Size() < objectSize {
		pod.Spec.Containers = append(pod.Spec.Containers, v1.Container{
			Name:                   rand.String(63),
			Image:                  rand.String(1000),
			WorkingDir:             rand.String(1000),
			TerminationMessagePath: rand.String(1000),
		})
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, v1.Container{
			Name:                   rand.String(63),
			Image:                  rand.String(1000),
			WorkingDir:             rand.String(1000),
			TerminationMessagePath: rand.String(1000),
		})
		pod.Spec.Volumes = append(pod.Spec.Volumes, v1.Volume{
			Name: rand.String(63),
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{
					Path: rand.String(1000),
				},
			},
		})
		pod.Status.Conditions = append(pod.Status.Conditions, v1.PodCondition{
			Reason: rand.String(1000),
		})
	}
	return pod
}
