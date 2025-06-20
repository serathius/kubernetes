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
var requestTimeout = time.Minute
var testDuration = requestTimeout + 20*time.Second

func main() {
	contentType := flag.String("content-type", "", "json or protobuf")
	resource := flag.String("resource", "", "configmap, pod, or cr")
	rev := flag.String("rv", "", "empty, zero, exact, continue")
	create := flag.Bool("create", false, "")
	pretty := flag.Bool("pretty", false, "")
	qps := flag.Float32("qps", 0, "")
	objectSize := flag.Int("object-size", 0, "")
	objectCount := flag.Int("object-count", 0, "")
	serviceAccount := flag.String("service-account", "", "")
	namespaces := flag.Int("namespaces", 1, "")
	limit := flag.Int("limit", 0, "")
	filter := flag.Bool("filter", false, "")
	clients := flag.Int("clients", 1, "")
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		fmt.Printf("failed to read kube config: %s\n", err)
		os.Exit(1)
	}
	config.QPS = -1
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
		if *qps == 0 {
			fmt.Printf("--qps needs to be set\n")
			os.Exit(1)
		}
		createResources(clientset, dynamicClient, *resource, *objectSize, *objectCount, *namespaces, *qps)
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
		namespace := "default"
		saName := *serviceAccount
		if strings.Contains(*serviceAccount, "/") {
			parts := strings.SplitN(*serviceAccount, "/", 2)
			namespace = parts[0]
			saName = parts[1]
		}
		token, err := createToken(clientset, namespace, saName)
		if err != nil {
			fmt.Printf("failed to create token: %s\n", err)
			os.Exit(1)
		}
		config.BearerToken = token
		config.TLSClientConfig.KeyData = []byte("")
	}

	var path string
	switch *resource {
	case "secret":
		path = "/api/v1/namespaces/%d/secrets"
	case "configmap":
		path = "/api/v1/namespaces/%d/configmaps"
	case "pod":
		path = "/api/v1/namespaces/%d/pods"
	case "cr":
		path = "/apis/stable.example.com/v1/namespaces/%d/crontabs"
	default:
		print("--resource should be set to \"configmap\", \"pod\" or \"cr\"\n")
		os.Exit(1)
	}
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
	if *pretty {
		if *contentType != "json" {
			panic("Pretty only supported for JSON")
		}
		params = append(params, "pretty=1")
	}
	if *limit != 0 {
		if *limit < 0 {
			panic("limit cannot be negative")
		}
		params = append(params, fmt.Sprintf("limit=%d", *limit))
	}
	if *filter {
		params = append(params, "labelSelector=app%3D0")
	}
	paramStr := strings.Join(params, "&")
	httpClients := make([]*http.Client, *clients)
	for i := 0; i < *clients; i++ {
		httpClients[i], err = rest.HTTPClientFor(config)
		if err != nil {
			fmt.Printf("failed to create client: %s\n", err)
			os.Exit(1)
		}
	}
	list(httpClients, path, config, *qps, serverURL, paramStr, *namespaces)
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

func createResources(clientset kubernetes.Interface, dynamicClient *dynamic.DynamicClient, resource string, objectSize, objectCount, namespaces int, qps float32) {
	gvr := schema.GroupVersionResource{
		Group:    "stable.example.com",
		Version:  "v1",
		Resource: "crontabs",
	}
	var wg sync.WaitGroup
	rateLimiter := rate.NewLimiter(rate.Limit(qps), 1)
	for i := 0; i < namespaces; i++ {
		namespace := fmt.Sprintf("%d", i)
		_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), randomNamespace(namespace), metav1.CreateOptions{})
		if err != nil {
			panic(err)
		}
		for j := 0; j < objectCount; j++ {
			_ = rateLimiter.WaitN(context.Background(), 1)
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				name := fmt.Sprintf("%d", j)
				var err error
				switch resource {
				case "pod":
					_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), randomPod(name, objectSize), metav1.CreateOptions{})
				case "cr":
					_, err = dynamicClient.Resource(gvr).Namespace(namespace).Create(context.TODO(), randomCR(name, objectSize), metav1.CreateOptions{})
				case "secret":
					_, err = clientset.CoreV1().Secrets(namespace).Create(context.TODO(), randomSecret(j, objectSize), metav1.CreateOptions{})
				case "configmap":
					_, err = clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), randomConfigmap(name, objectSize), metav1.CreateOptions{})
				default:
					print("--resource should be set to \"configmap\", \"pod\" or \"cr\"\n")
				}
				if err != nil {
					panic(err)
				}
			}(j)
		}
	}
	wg.Wait()
	fmt.Printf("Created %ss\n", resource)
}

func list(clients []*http.Client, pathTemplate string, config *rest.Config, qps float32, serverURL *url.URL, params string, namespaces int) {
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
				path := fmt.Sprintf(pathTemplate, i%namespaces)
				if params != "" {
					path = fmt.Sprintf("%s?%s", path, params)
				}

				url, err := url.Parse(path)
				if err != nil {
					panic(err)
				}
				url.Host = serverURL.Host
				url.Scheme = serverURL.Scheme
				reqCtx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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
				if resp.StatusCode == 504 {
					fmt.Print("Bad gateway\n")
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
				"name": name,
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
