/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/endpoints/request"
	webhookutil "k8s.io/apiserver/pkg/util/webhook"
	v1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

func newGKETokenAuthenticator(serverURL string, clientCert, clientKey, ca []byte, cacheTime time.Duration, implicitAuds authenticator.Audiences, metrics AuthenticatorMetrics) (authenticator.Token, error) {
	tempfile, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	p := tempfile.Name()
	defer os.Remove(p)

	config := v1.Config{
		Clusters: []v1.NamedCluster{
			{
				Cluster: v1.Cluster{Server: serverURL, CertificateAuthorityData: ca},
			},
		},
		AuthInfos: []v1.NamedAuthInfo{
			{
				AuthInfo: v1.AuthInfo{ClientCertificateData: clientCert, ClientKeyData: clientKey},
			},
		},
	}
	if err := json.NewEncoder(tempfile).Encode(config); err != nil {
		return nil, err
	}

	clientConfig, err := webhookutil.LoadKubeconfig(p, nil)
	if err != nil {
		return nil, err
	}

	c, err := tokenReviewInterfaceFromConfig(clientConfig, "v1beta1", testRetryBackoff)
	if err != nil {
		return nil, err
	}

	authn, err := newWithBackoff(c, testRetryBackoff, implicitAuds, 10*time.Second, metrics)
	if err != nil {
		return nil, err
	}

	authn.gkeHooks.decorateReview = setRequestIPAddr

	return cache.New(authn, false, cacheTime, cacheTime), nil
}

func TestRemoteAddrForwarding(t *testing.T) {
	serv := &recorderV1beta1Service{}

	s, err := NewV1beta1TestServer(serv, serverCert, serverKey, caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		description    string
		requestInfo    request.RequestInfo
		wantAnnotation string
	}{
		{
			description: "successfully pass remote address.",
			requestInfo: request.RequestInfo{
				RemoteAddr: "192.255.255.255",
			},
			wantAnnotation: "192.255.255.255",
		},
		{
			description: "empty request info",
			requestInfo: request.RequestInfo{},
		},
		{
			description: "no request info",
		},
	}
	token := "my-s3cr3t-t0ken" // Fake token for testing.
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			wh, err := newGKETokenAuthenticator(s.URL, clientCert, clientKey, caCert, 0, []string{"api"}, noopAuthenticatorMetrics())
			if err != nil {
				t.Fatal(err)
			}

			ctx := request.WithRequestInfo(context.Background(), &tt.requestInfo)
			info, ok := request.RequestInfoFrom(ctx)
			t.Log(ok)
			t.Log(info)

			serv.response = authenticationv1beta1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1beta1.UserInfo{
					Username: "somebody",
				},
			}
			if _, _, err := wh.AuthenticateToken(ctx, token); err != nil {
				t.Fatalf("authentication failed: %v", err)
			}
			if got, want := serv.lastRequest.ObjectMeta.Annotations["iam.gke.io/request-ip-address"], tt.wantAnnotation; got != want {
				t.Errorf("unexpected diff in annotations: got=%v, want=%v", got, want)
			}
		})
	}
}

func TestIsGKEWebhookHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{name: "gke prod", host: "container.googleapis.com", expected: true},
		{name: "gke staging", host: "staging-container.sandbox.googleapis.com", expected: true},
		{name: "gke staging2", host: "staging2-container.sandbox.googleapis.com", expected: true},
		{name: "gke test", host: "test-container.sandbox.googleapis.com", expected: true},
		{name: "gke sandbox", host: "some-gke-sandbox-test-container.sandbox.googleapis.com", expected: true},
		{name: "gke auth prod", host: "gkeauth.googleapis.com", expected: true},
		{name: "gke auth preprod", host: "preprod-gkeauth.sandbox.googleapis.com", expected: true},
		{name: "gke auth staging", host: "staging-gkeauth.sandbox.googleapis.com", expected: true},
		{name: "gke auth autopush", host: "autopush-gkeauth.sandbox.googleapis.com", expected: true},
		{name: "not gke", host: "anthos.googleapis.com", expected: false},
		{name: "other url", host: "some-other-domain.com", expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := isGKEWebhookHost(fmt.Sprintf("https://%s/", test.host))
			if test.expected != decision {
				t.Errorf("expected %v, got %v", test.expected, decision)
			}
		})
	}
}
