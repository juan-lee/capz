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
	capierrors "sigs.k8s.io/cluster-api/errors"
)

const (
	// MachinePoolFinalizer allows AzureMachinePoolReconciler to clean up Azure resources
	// associated with AzureMachinePool before removing it from the apiserver.
	AzureMachinePoolFinalizer = "azuremachinepool.infrastructure.cluster.x-k8s.io"
)

// AzureMachinePoolSpec defines the desired state of AzureMachinePool
type AzureMachinePoolSpec struct {
	// ResourceGroup
	ResourceGroup ResourceGroup `json:"resourceGroup,omitempty"`

	// Name
	Name string `json:"name,omitempty"`

	// SKU
	SKU string `json:"sku,omitempty"`

	// SSHPublicKey
	SSHPublicKey string `json:"sshPublicKey,omitempty"`

	// Subnet
	Subnet string `json:"subnet,omitempty"`

	// ProviderIDList is the unique identifier as specified by the cloud provider.
	// +optional
	ProviderIDList []string `json:"providerIDList,omitempty"`
}

// AzureMachinePoolStatus defines the observed state of AzureMachinePool
type AzureMachinePoolStatus struct {
	// Replicas is the most recently observed number of replicas.
	// +optional
	Replicas int32 `json:"replicas"`

	// Any transient errors that occur during the reconciliation of Machines
	// can be added as events to the Machine object and/or logged in the
	// controller's output.
	// +optional
	ErrorReason *capierrors.MachineStatusError `json:"errorReason,omitempty"`

	// Any transient errors that occur during the reconciliation of Machines
	// can be added as events to the Machine object and/or logged in the
	// controller's output.
	// +optional
	ErrorMessage *string `json:"errorMessage,omitempty"`

	// Ready is true when the provider resource is ready.
	// +optional
	Ready bool `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Replicas",type="string",JSONPath=".status.replicas",description="AzureMachinePool replicas count"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.ready",description="AzureMachinePool replicas count"

// AzureMachinePool is the Schema for the azuremachinepools API
type AzureMachinePool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureMachinePoolSpec   `json:"spec,omitempty"`
	Status AzureMachinePoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AzureMachinePoolList contains a list of AzureMachinePool
type AzureMachinePoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureMachinePool `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AzureMachinePool{}, &AzureMachinePoolList{})
}
