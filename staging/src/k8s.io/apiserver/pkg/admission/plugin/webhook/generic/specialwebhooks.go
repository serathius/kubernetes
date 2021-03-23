/*
Copyright 2018 The Kubernetes Authors.

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

/*
specialwebhooks.go contains utility functions that are used for enabling special
webhooks which intercept other webhooks, and are initially introduced as an
internal patch on GKE fork (see b/184065096)
*/

package generic

import (
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/webhook"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

const (
	// The name of the file which contains the special webhooks config.
	specialWebhooksConfigFile string = "/etc/srv/kubernetes/specialwebhooks-config.yaml"
)

// WebhookIdentifier is used to uniquely identify a webhook across all
// registered webhooks. A webhook's name by itself is not enough to do so, as
// webhookconfigurations with different types or names could have webhooks with
// the same name.
type WebhookIdentifier struct {
	IsMutating        bool
	ConfigurationName string
	Name              string
}

// specialWebhooksConfig is used to load the configuration from file.
type specialWebhooksConfig struct {
	// SpecialWebhookIdentifiers specifies the special webhooks.
	SpecialWebhookIdentifiers []WebhookIdentifier `json:"specialWebhookIdentifiers"`
	// SpecialWebhookMaintainers consist of identities which maintain (i.e.
	// could add/delete/modify) the special webhooks. Normally webhook admission
	// requests are intercepted by special webhooks, and could potentially be
	// denied (for instance when the webhook is misconfigured). However,
	// requests made by maintainers will *not* be intercepted by special
	// webhooks, enabling them to maintain these webhooks. A request is
	// considered to be made by a maintainer if either its username is in Users,
	// or one of its groups is in Groups.
	SpecialWebhookMaintainers struct {
		Users  []string `json:"users"`
		Groups []string `json:"groups"`
	} `json:"specialWebhookMaintainers"`
	// ExemptResources is a list of resources that will be exempt (e.g. not
	// dispatched) when intercepted by any webhooks (including special
	// webhooks).
	ExemptResources []metav1.GroupResource `json:"exemptResources"`
}

// specialWebhooksPrecomputedConfig contains configuration data for special
// webhooks that are precomputed at startup (consuming a specialWebhooksConfig
// object) and provide data-structures for efficient lookups.
type specialWebhooksPrecomputedConfig struct {
	maintainerUsersSet  sets.String
	maintainerGroupsSet sets.String
	// specialWebhookStringIDSet is a set of strings, each computed by
	// `buildWebhookStringID` and uniquely identifies a special webhook. This
	// set allows efficient search of special webhooks.
	specialWebhookStringIDSet sets.String
	// exemptResourcesMap is a map of GroupResource, each representing a
	// resource defined in ExemptResources.
	exemptResourcesMap map[schema.GroupResource]bool
}

// buildWebhookStringID is used for precomputing and searching
// specialWebhookStringIDSet.
func buildWebhookStringID(isMutating bool, configurationName, name string) string {
	whType := "v" // short for validating.
	if isMutating {
		whType = "m" // short for mutating.
	}
	return fmt.Sprintf(`%s\0%s\0%s`, whType, configurationName, name)
}

// loadAndPrecomputeSpecialWebhooksConfig loads special webhooks' config from
// the given file, and precomputes the data-structures used for efficient
// lookups.
func loadAndPrecomputeSpecialWebhooksConfig(configFile string) (precomputedConfig *specialWebhooksPrecomputedConfig, err error) {
	configYaml, err := os.ReadFile(configFile)
	if os.IsNotExist(err) {
		// If the file doesn't exist, specialwebhooks is not enabled.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	config := &specialWebhooksConfig{}
	if err := yaml.Unmarshal(configYaml, config); err != nil {
		return nil, err
	}

	// populate specialWebhooksPrecomputedConfig.
	whStringIDs := []string{}
	for _, whID := range config.SpecialWebhookIdentifiers {
		whStringIDs = append(whStringIDs, buildWebhookStringID(whID.IsMutating, whID.ConfigurationName, whID.Name))
	}

	exemptResourcesMap := map[schema.GroupResource]bool{}
	for _, r := range config.ExemptResources {
		exemptResourcesMap[schema.GroupResource{Group: r.Group, Resource: r.Resource}] = true
	}

	defer func() {
		klog.V(0).Infof("loaded and precomputed SpecialWebhooks config: %v", precomputedConfig)
	}()

	return &specialWebhooksPrecomputedConfig{
		maintainerUsersSet:        sets.NewString(config.SpecialWebhookMaintainers.Users...),
		maintainerGroupsSet:       sets.NewString(config.SpecialWebhookMaintainers.Groups...),
		specialWebhookStringIDSet: sets.NewString(whStringIDs...),
		exemptResourcesMap:        exemptResourcesMap,
	}, nil
}

// specialWebhooksFilter returns a filter for the registered webhooks
// objects. This is only called when the admission request is normally not
// intercepted by other webhooks (e.g. a webhook admission request), and this
// method is used to filter out the special webhooks which could do so. A nil is
// returned if the filter should discard all items (i.e. no webhook will
// intercept the request).
func (a *Webhook) specialWebhooksFilter(attr admission.Attributes) func(input []webhook.WebhookAccessor) []webhook.WebhookAccessor {
	// Exit early if the config is not loaded, or no any special webhook is set.
	if a.specialWebhooksPrecomputedConfig == nil ||
		a.specialWebhooksPrecomputedConfig.specialWebhookStringIDSet.Len() == 0 {
		return nil
	}
	// Exit early if the requestor is a maintainer.
	userInfo := attr.GetUserInfo()
	if a.specialWebhooksPrecomputedConfig.maintainerUsersSet.Has(userInfo.GetName()) ||
		a.specialWebhooksPrecomputedConfig.maintainerGroupsSet.HasAny(userInfo.GetGroups()...) {
		return nil
	}
	return func(input []webhook.WebhookAccessor) []webhook.WebhookAccessor {
		var hooks []webhook.WebhookAccessor
		for _, h := range input {
			_, isMutating := h.GetMutatingWebhook()
			whID := buildWebhookStringID(isMutating, h.GetConfigurationName(), h.GetName())
			if a.specialWebhooksPrecomputedConfig.specialWebhookStringIDSet.Has(whID) {
				hooks = append(hooks, h)
			}
		}
		return hooks
	}
}

// isExemptResource returns true if the input resource is in the list of
// configured exempt resources.
func (a *Webhook) isExemptResource(attr admission.Attributes) bool {
	// Exit early if the config is not loaded, or no any exempt resources are set.
	if a.specialWebhooksPrecomputedConfig == nil ||
		len(a.specialWebhooksPrecomputedConfig.exemptResourcesMap) == 0 {
		return false
	}

	return a.specialWebhooksPrecomputedConfig.exemptResourcesMap[attr.GetResource().GroupResource()]
}
