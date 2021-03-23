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

package generic

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/webhook"
	"k8s.io/apiserver/pkg/authentication/user"
)

type mockDispatcher struct {
	dispatchHooks []webhook.WebhookAccessor
	*admission.Handler
}

func (m *mockDispatcher) Dispatch(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces, hooks []webhook.WebhookAccessor) error {
	m.dispatchHooks = hooks
	return nil
}

var _ Dispatcher = &mockDispatcher{}

type mockAttribute struct {
	name     string
	group    string
	version  string
	resource string
	kind     string
	admission.Attributes
	userInfo user.Info
}

func (a *mockAttribute) GetName() string {
	return a.name
}
func (a *mockAttribute) GetKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   a.group,
		Version: a.version,
		Kind:    a.kind,
	}
}
func (a *mockAttribute) GetUserInfo() user.Info {
	return a.userInfo
}

func (a *mockAttribute) GetResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    a.group,
		Version:  a.version,
		Resource: a.resource,
	}
}

var _ admission.Attributes = &mockAttribute{}

type mockSource struct {
	hooks []webhook.WebhookAccessor
	Source
}

func (m *mockSource) Webhooks() []webhook.WebhookAccessor {
	return m.hooks
}

var _ Source = &mockSource{}

type mockUserInfo struct {
	user.Info
	name   string
	groups []string
}

func (u *mockUserInfo) GetName() string     { return u.name }
func (u *mockUserInfo) GetGroups() []string { return u.groups }

var _ user.Info = &mockUserInfo{}

type mockWebhookAccessor struct {
	Name       string
	ConfName   string
	IsMutating bool
	webhook.WebhookAccessor
}

func (m *mockWebhookAccessor) GetName() string {
	return m.Name
}

func (m *mockWebhookAccessor) GetMutatingWebhook() (*v1.MutatingWebhook, bool) {
	return nil, m.IsMutating
}

func (m *mockWebhookAccessor) GetConfigurationName() string {
	return m.ConfName
}

var _ webhook.WebhookAccessor = &mockWebhookAccessor{}

func TestLoadAndPrecomputeSpecialWebhooksConfig(t *testing.T) {
	sampleValidConfig := `
specialWebhookIdentifiers:
  - isMutating: true
    configurationName: config-b
    name: webhook-a
  - isMutating: false
    configurationName: config-a
    name: webhook-a
specialWebhookMaintainers:
  users:
    - user-a
    - user-b
  groups:
    - group-x
exemptResources:
  - group: authentication.k8s.io
    resource: tokenreviews
  - group: mygroup.myorg.io
    resource: gadgets
`
	configFile, err := ioutil.TempFile("", "admission-plugin-config")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	configFileName := configFile.Name()
	defer os.Remove(configFileName)

	if err = configFile.Close(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	for name, tc := range map[string]struct {
		configFileName string
		configBody     string
		expectedConfig *specialWebhooksPrecomputedConfig
		expectedErr    error
	}{
		"ValidConfig_ReturnsExpected": {
			configBody: sampleValidConfig,
			expectedConfig: &specialWebhooksPrecomputedConfig{
				maintainerUsersSet:  sets.NewString("user-a", "user-b"),
				maintainerGroupsSet: sets.NewString("group-x"),
				specialWebhookStringIDSet: sets.NewString(
					`v\0config-a\0webhook-a`,
					`m\0config-b\0webhook-a`),
				exemptResourcesMap: map[schema.GroupResource]bool{
					{Group: "authentication.k8s.io", Resource: "tokenreviews"}: true,
					{Group: "mygroup.myorg.io", Resource: "gadgets"}:           true,
				},
			},
			expectedErr: nil,
		},
		"EmptyConfig_ReturnsEmptyConfig": {
			configBody: "",
			expectedConfig: &specialWebhooksPrecomputedConfig{
				exemptResourcesMap: map[schema.GroupResource]bool{},
			},
			expectedErr: nil,
		},
		"NonExistingConfig_ReturnsNilConfig": {
			configFileName: "/a/non/existing/path/config.yaml",
			configBody:     "specialWebhookIdentifiers: []",
			expectedConfig: nil,
			expectedErr:    nil,
		},
		"InvalidConfigBody_ReturnsError": {
			configBody:     "specialWebhookIdentifiers: []]",
			expectedConfig: nil,
			expectedErr:    fmt.Errorf("error converting YAML to JSON: yaml: did not find expected key"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.configFileName == "" {
				tc.configFileName = configFileName
			}
			if err = ioutil.WriteFile(configFileName, []byte(tc.configBody), 0644); err != nil {
				t.Fatalf("unexpected err writing temp file: %v", err)
			}

			observedConfig, observedErr := loadAndPrecomputeSpecialWebhooksConfig(tc.configFileName)
			if diff := cmp.Diff(tc.expectedConfig, observedConfig, cmpopts.IgnoreUnexported(specialWebhooksPrecomputedConfig{})); diff != "" {
				t.Errorf("loadAndPrecomputeSpecialWebhooksConfig (...): -want set, +got set:\n%s", diff)
			}
			if tc.expectedConfig != nil && observedConfig != nil {
				if diff := cmp.Diff(tc.expectedConfig.maintainerUsersSet, observedConfig.maintainerUsersSet); diff != "" {
					t.Errorf("loadAndPrecomputeSpecialWebhooksConfig (...): -want maintainerUsersSet set, +got maintainerUsersSet set:\n%s", diff)
				}
				if diff := cmp.Diff(tc.expectedConfig.maintainerGroupsSet, observedConfig.maintainerGroupsSet); diff != "" {
					t.Errorf("loadAndPrecomputeSpecialWebhooksConfig (...): -want maintainerGroupsSet set, +got maintainerGroupsSet set:\n%s", diff)
				}
				if diff := cmp.Diff(tc.expectedConfig.specialWebhookStringIDSet, observedConfig.specialWebhookStringIDSet); diff != "" {
					t.Errorf("loadAndPrecomputeSpecialWebhooksConfig (...): -want specialWebhookStringIDSet set, +got specialWebhookStringIDSet set:\n%s", diff)
				}
				if diff := cmp.Diff(tc.expectedConfig.exemptResourcesMap, observedConfig.exemptResourcesMap); diff != "" {
					t.Errorf("loadAndPrecomputeSpecialWebhooksConfig (...): -want exemptResourcesSet set, +got specialWebhookStringIDSet set:\n%s", diff)
				}
			}
			if diff := cmp.Diff(fmt.Sprintf("%v", tc.expectedErr), fmt.Sprintf("%v", observedErr)); diff != "" {
				t.Errorf("loadAndPrecomputeSpecialWebhooksConfig (...): -want error, +got error:\n%s", diff)
			}
		})
	}
}

func TestSpecialWebhooksFilter(t *testing.T) {
	for name, tc := range map[string]struct {
		registeredHooks []webhook.WebhookAccessor
		config          *specialWebhooksPrecomputedConfig
		expectedHooks   []webhook.WebhookAccessor
	}{
		"SpecialWebhooksConfigNil_ReturnsNil": {
			registeredHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "m-webhook-a"},
			},
			config:        nil,
			expectedHooks: nil,
		},
		"SpecialWebhookIdentifiersEmpty_ReturnsNil": {
			registeredHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "m-webhook-a"},
			},
			config:        &specialWebhooksPrecomputedConfig{},
			expectedHooks: nil,
		},
		"SpecialWebhookIdentifiersNonEmpty_UserIsMaintainer_ReturnsNil": {
			registeredHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "webhook-a"},
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-b", Name: "webhook-c"},
			},
			config: &specialWebhooksPrecomputedConfig{
				specialWebhookStringIDSet: sets.NewString(`m\0config-a\0webhook-a`, `v\0config-b\0webhook-c`),
				maintainerUsersSet:        sets.NewString("user-a", "user-b"),
			},
			expectedHooks: nil,
		},
		"SpecialWebhookIdentifiersNonEmpty_GroupIsMaintainer_ReturnsNil": {
			registeredHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "webhook-a"},
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-b", Name: "webhook-c"},
			},
			config: &specialWebhooksPrecomputedConfig{
				specialWebhookStringIDSet: sets.NewString(`m\0config-a\0webhook-a`, "v_config-b_webhook-c"),
				maintainerGroupsSet:       sets.NewString("group-b", "group-f", "group-n"),
			},
			expectedHooks: nil,
		},
		"SpecialWebhookIdentifiersNonEmpty_MatchingRegisteredHooks_ReturnsExpected": {
			registeredHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "webhook-a"},  // (1)
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-b", Name: "webhook-c"},  // (2)
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-b", Name: "webhook-b"},  // (3)
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-x", Name: "webhook-d"}, // (4)
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-y", Name: "webhook-e"},  // (5)
			},
			config: &specialWebhooksPrecomputedConfig{
				specialWebhookStringIDSet: sets.NewString(
					`m\0config-a\0webhook-c`, // type and config matches (1), but name doesn't.
					`m\0config-a\0webhook-c`, // type and name matches (2), but config doesn't.
					`v\0config-b\0webhook-b`, // config and name matches (3), but type doesn't.
					`v\0config-x\0webhook-d`, // matches (4).
					`m\0config-y\0webhook-e`, // matches (5).
				),
			},
			expectedHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-x", Name: "webhook-d"},
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-y", Name: "webhook-e"},
			},
		},
		"SpecialWebhookIdentifiersNonEmpty_NoMatchingRegisteredHooks_ReturnsNil": {
			registeredHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "webhook-a"},
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-b", Name: "webhook-b"},
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-c", Name: "webhook-b"},
			},
			config: &specialWebhooksPrecomputedConfig{
				specialWebhookStringIDSet: sets.NewString(`v\0config-a\0webhook-a`, `m\0config-x\0webhook-a`, `m\0config-a\0webhook-x`),
			},
			expectedHooks: nil,
		},
		"NoRegisteredHooks_ReturnsNil": {
			registeredHooks: nil,
			config: &specialWebhooksPrecomputedConfig{
				specialWebhookStringIDSet: sets.NewString(`m\0config-a\0webhook-c`, `v\0config-b\0webhook-c`),
			},
			expectedHooks: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			mockWebhook := &Webhook{
				specialWebhooksPrecomputedConfig: tc.config,
			}

			admissionRequestUserInfo := &mockUserInfo{
				name:   "user-a",
				groups: []string{"group-a", "group-b"},
			}

			observedFilter := mockWebhook.specialWebhooksFilter(&mockAttribute{userInfo: admissionRequestUserInfo})
			if observedFilter != nil {
				observedHooks := observedFilter(tc.registeredHooks)
				if diff := cmp.Diff(tc.expectedHooks, observedHooks); diff != "" {
					t.Errorf("getSpecialHooksFilter (...)(registeredHooks): -want hooks, +got hooks:\n%s", diff)
				}
			} else {
				if tc.expectedHooks != nil {
					t.Errorf("getSpecialHooksFilter (...): want nil, got non-nil")
				}
			}
		})
	}
}

func TestDispatch(t *testing.T) {
	sampleWebhookAttr := &mockAttribute{
		group:    "admissionregistration.k8s.io",
		kind:     "ValidatingWebhookConfiguration",
		resource: "validatingwebhookconfigurations",
		userInfo: &mockUserInfo{
			name:   "a-user",
			groups: []string{"gr1", "gr2"},
		},
	}
	exemptObjectAttr := &mockAttribute{
		group:    "authentication.k8s.io",
		kind:     "TokenReview",
		resource: "tokenreviews",
		userInfo: &mockUserInfo{
			name:   "a-user",
			groups: []string{"gr1", "gr2"},
		},
	}

	sampleRegisteredHooks := []webhook.WebhookAccessor{
		&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "webhook-a"},
		&mockWebhookAccessor{IsMutating: true, ConfName: "config-b", Name: "webhook-a"},
		&mockWebhookAccessor{IsMutating: false, ConfName: "config-b", Name: "webhook-b"},
	}

	for name, tc := range map[string]struct {
		incomingAttr            *mockAttribute
		specialWebhookIDs       sets.String
		exemptResourcesMap      map[schema.GroupResource]bool
		registeredHooks         []webhook.WebhookAccessor
		expectedDispatchedHooks []webhook.WebhookAccessor
	}{
		"InterceptedObjectIsNotWebhook_DispatchCalled": {
			specialWebhookIDs: sets.NewString(`m\0config-a\0webhook-a`, `v\0config-b\0webhook-b`),
			incomingAttr: &mockAttribute{
				group:    "apps",
				kind:     "Deployment",
				resource: "deployments",
			},
			registeredHooks:         sampleRegisteredHooks,
			expectedDispatchedHooks: sampleRegisteredHooks,
		},
		"InterceptedObjectIsWebhook_EmptySpecialWebhooksIdentifiers_DispatchNotCalled": {
			specialWebhookIDs:       sets.NewString(),
			incomingAttr:            sampleWebhookAttr,
			registeredHooks:         sampleRegisteredHooks,
			expectedDispatchedHooks: nil,
		},
		"InterceptedObjectIsExempt_EmptySpecialWebhooksIdentifiers_DispatchNotCalled": {
			specialWebhookIDs: sets.NewString(),
			incomingAttr:      exemptObjectAttr,
			exemptResourcesMap: map[schema.GroupResource]bool{
				{
					Group:    "authentication.k8s.io",
					Resource: "tokenreviews",
				}: true,
			},
			registeredHooks:         sampleRegisteredHooks,
			expectedDispatchedHooks: nil,
		},
		"InterceptedObjectIsWebhook_MatchingSpecialWebhooksIdentifiers_DispatchCalled": {
			specialWebhookIDs: sets.NewString(`m\0config-a\0webhook-a`, `v\0config-b\0webhook-b`),
			incomingAttr:      sampleWebhookAttr,
			registeredHooks:   sampleRegisteredHooks,
			expectedDispatchedHooks: []webhook.WebhookAccessor{
				&mockWebhookAccessor{IsMutating: true, ConfName: "config-a", Name: "webhook-a"},
				&mockWebhookAccessor{IsMutating: false, ConfName: "config-b", Name: "webhook-b"},
			},
		},
		"InterceptedObjectIsExempt_MatchingSpecialWebhooksIdentifiers_DispatchNotCalled": {
			specialWebhookIDs: sets.NewString(`m\0config-a\0webhook-a`, `v\0config-b\0webhook-b`),
			incomingAttr:      exemptObjectAttr,
			exemptResourcesMap: map[schema.GroupResource]bool{
				{
					Group:    "authentication.k8s.io",
					Resource: "tokenreviews",
				}: true,
			},
			registeredHooks:         sampleRegisteredHooks,
			expectedDispatchedHooks: nil,
		},
		"InterceptedObjectIsWebhook_NonMatchingSpecialWebhooksIdentifiers_DispatchNotCalled": {
			specialWebhookIDs:       sets.NewString(`v\0config-a\0webhook-a`, `m\0config-x\0webhook-a`),
			incomingAttr:            sampleWebhookAttr,
			registeredHooks:         sampleRegisteredHooks,
			expectedDispatchedHooks: nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			md := &mockDispatcher{}
			mockWebhook := &Webhook{
				dispatcher: md,
				hookSource: &mockSource{
					hooks: tc.registeredHooks,
				},
				Handler: &admission.Handler{},
				specialWebhooksPrecomputedConfig: &specialWebhooksPrecomputedConfig{
					specialWebhookStringIDSet: tc.specialWebhookIDs,
					exemptResourcesMap:        tc.exemptResourcesMap,
				},
			}

			mockWebhook.Dispatch(context.TODO(), tc.incomingAttr, nil)
			if diff := cmp.Diff(tc.expectedDispatchedHooks, md.dispatchHooks); diff != "" {
				t.Errorf("genericwebhook.Dispatch (...): -want hooks, +got hooks:\n%s", diff)
			}
		})
	}
}
