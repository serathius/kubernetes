package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"golang.org/x/net/http2"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
	"k8s.io/client-go/util/homedir"
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
	acceptEncoding := flag.String("accept-encoding", "", "Accept-Encoding header value")
	serial := flag.Bool("serial", false, "Run requests serially")
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
	if *qps == 0 && !*serial {
		fmt.Printf("--qps or --serial needs to be set\n")
		os.Exit(1)
	}
	if *qps != 0 && *serial {
		fmt.Printf("Cannot set both --qps and --serial\n")
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
		if err := transportHack(config); err != nil {
			panic(err)
		}
		httpClients[i], err = rest.HTTPClientFor(config)
		if err != nil {
			fmt.Printf("failed to create client: %s\n", err)
			os.Exit(1)
		}
	}
	switch *acceptEncoding {
	case "":
	case "gzip":
	case "pgzip":
	case "kgzip":
	case "s2":
	default:
		fmt.Printf(`--accept-encoding should be set to "gzip", "pgzip", "kgzip", or "s2"
`)
		os.Exit(1)
	}
	lister := NewLister(httpClients, path, config, *qps, serverURL, paramStr, *namespaces, *acceptEncoding, *serial)
	stats := lister.Run(*serial, *qps)
	stats.printStats(testDuration)
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

func transportHack(config *rest.Config) error {
	// For the purpose of this test, we want to force that clients
	// do not share underlying transport (which is a default behavior
	// in Kubernetes). Thus, we are explicitly creating transport for
	// each client here.
	transportConfig, err := config.TransportConfig()
	if err != nil {
		return err
	}
	tlsConfig, err := transport.TLSConfigFor(transportConfig)
	if err != nil {
		return err
	}
	t := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: 100,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	utilnet.SetOldTransportDefaults(t)
	_, err = http2.ConfigureTransports(t)
	if err != nil {
		return err
	}
	// t2.MaxReadFrameSize = 1 << 20 // 1MB
	// t2.AllowHTTP = true

	config.Transport = t
	config.WrapTransport = transportConfig.WrapTransport
	if transportConfig.DialHolder != nil {
		config.Dial = transportConfig.DialHolder.Dial
	}
	// Overwrite TLS-related fields from config to avoid collision with
	// Transport field.
	config.TLSClientConfig = rest.TLSClientConfig{}
	config.AuthProvider = nil
	config.ExecProvider = nil

	return nil
}
