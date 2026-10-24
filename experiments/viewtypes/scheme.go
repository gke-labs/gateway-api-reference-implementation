// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package viewtypes

import (
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

var (
	// CoreGroupVersion is the group version for core Kubernetes types (v1).
	CoreGroupVersion = schema.GroupVersion{Group: "", Version: "v1"}

	// GatewayGroupVersion is the group version for Gateway API (gateway.networking.k8s.io/v1).
	GatewayGroupVersion = schema.GroupVersion{Group: "gateway.networking.k8s.io", Version: "v1"}
)

// NewScheme constructs a dedicated runtime.Scheme mapping Kubernetes kinds to read-only view types.
func NewScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	// Register core view types under their canonical Kubernetes kind names
	scheme.AddKnownTypeWithName(CoreGroupVersion.WithKind("ConfigMap"), &ConfigMapView{})
	scheme.AddKnownTypeWithName(CoreGroupVersion.WithKind("ConfigMapList"), &ConfigMapViewList{})
	scheme.AddKnownTypeWithName(CoreGroupVersion.WithKind("Secret"), &SecretView{})
	scheme.AddKnownTypeWithName(CoreGroupVersion.WithKind("SecretList"), &SecretViewList{})
	metav1.AddToGroupVersion(scheme, CoreGroupVersion)

	// Register Gateway API view types under their canonical Kubernetes kind names
	scheme.AddKnownTypeWithName(GatewayGroupVersion.WithKind("HTTPRoute"), &HTTPRouteView{})
	scheme.AddKnownTypeWithName(GatewayGroupVersion.WithKind("HTTPRouteList"), &HTTPRouteViewList{})
	metav1.AddToGroupVersion(scheme, GatewayGroupVersion)

	return scheme
}

// NewCodecs creates a serializer.CodecFactory for the given scheme.
func NewCodecs(scheme *runtime.Scheme) serializer.CodecFactory {
	return serializer.NewCodecFactory(scheme)
}

// NewRESTClient creates a client-go RESTClient targeting the specified API group/version using view types.
func NewRESTClient(baseURL string, gv schema.GroupVersion, scheme *runtime.Scheme, httpClient *http.Client) (*rest.RESTClient, error) {
	codecs := NewCodecs(scheme)

	var apiPath string
	if gv.Group == "" {
		apiPath = "/api"
	} else {
		apiPath = "/apis"
	}

	config := &rest.Config{
		Host:    baseURL,
		APIPath: apiPath,
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &gv,
			NegotiatedSerializer: codecs.WithoutConversion(),
			ContentType:          runtime.ContentTypeJSON,
		},
	}

	if httpClient != nil {
		return rest.RESTClientForConfigAndClient(config, httpClient)
	}
	return rest.RESTClientFor(config)
}
