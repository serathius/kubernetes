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
	"regexp"

	authenticationv1 "k8s.io/api/authentication/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
)

var hostNameRegex = regexp.MustCompile(`^https://[^/]*(container|gkeauth)\.(sandbox\.)?googleapis.com/`)

func NewGKE(config *rest.Config, version string, implicitAuds authenticator.Audiences, retryBackoff wait.Backoff, customDial utilnet.DialFunc) (*WebhookTokenAuthenticator, error) {
	authenticator, err := New(config, version, implicitAuds, retryBackoff)
	if err != nil {
		return nil, err
	}
	// Check if running on GKE
	if isGKEWebhookHost(config.Host) {
		authenticator.gkeHooks.decorateReview = setRequestIPAddr
	}
	return authenticator, nil
}

type gkeHooks struct {
	decorateReview func(context.Context, *authenticationv1.TokenReview)
}

// isGKEWebhookHost checks if the host matches GKE control plane
func isGKEWebhookHost(host string) bool {
	return hostNameRegex.MatchString(host)
}

func setRequestIPAddr(ctx context.Context, tr *authenticationv1.TokenReview) {
	var ipAddr = ""
	if req, ok := request.RequestInfoFrom(ctx); ok {
		ipAddr = req.RemoteAddr
	}
	if tr.ObjectMeta.Annotations == nil {
		tr.ObjectMeta.Annotations = make(map[string]string)
	}
	tr.ObjectMeta.Annotations["iam.gke.io/request-ip-address"] = ipAddr
}

func (w *WebhookTokenAuthenticator) maybeDecorateReview(ctx context.Context, tr *authenticationv1.TokenReview) {
	if w.gkeHooks.decorateReview != nil {
		w.gkeHooks.decorateReview(ctx, tr)
	}
}
