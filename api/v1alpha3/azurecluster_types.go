/*
Copyright 2019 The Kubernetes Authors.

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

package v1alpha3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capiv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
	capierrors "sigs.k8s.io/cluster-api/errors"
)

const (
	// ClusterFinalizer allows AzureClusterReconciler to clean up Azure resources
	// associated with AzureCluster before removing it from the apiserver.
	ClusterFinalizer = "azurecluster.infrastructure.cluster.x-k8s.io"
)

// AzureClusterSpec defines the desired state of AzureCluster
type AzureClusterSpec struct {
	// ControlPlaneEndpoint
	// +optional
	ControlPlaneEndpoint capiv1.APIEndpoint `json:"controlPlaneEndpoint,omitempty"`

	// ResourceGroup
	ResourceGroup ResourceGroup `json:"resourceGroup,omitempty"`

	// Network
	Network Network `json:"network,omitempty"`
}

// AzureClusterStatus defines the observed state of AzureCluster
type AzureClusterStatus struct {
	// ErrorReason indicates that there is a problem reconciling the
	// state, and will be set to a token value suitable for
	// programmatic interpretation.
	// +optional
	ErrorReason *capierrors.ClusterStatusError `json:"errorReason,omitempty"`

	// ErrorMessage indicates that there is a problem reconciling the
	// state, and will be set to a descriptive error message.
	// +optional
	ErrorMessage *string `json:"errorMessage,omitempty"`

	// Ready indicates that the cluster infrastructure was successfully provisioned.
	Ready bool `json:"ready"`

	// FailureDomains
	// +optional
	FailureDomains capiv1.FailureDomains `json:"failureDomains,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AzureCluster is the Schema for the azureclusters API
type AzureCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureClusterSpec   `json:"spec,omitempty"`
	Status AzureClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AzureClusterList contains a list of AzureCluster
type AzureClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureCluster `json:"items"`
}

func init() { // nolint: gochecknoinits
	SchemeBuilder.Register(&AzureCluster{}, &AzureClusterList{})
}
