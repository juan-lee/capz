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
	// MachineFinalizer allows AzureMachineReconciler to clean up Azure resources
	// associated with AzureMachine before removing it from the apiserver.
	MachineFinalizer = "azuremachine.infrastructure.cluster.x-k8s.io"
)

// AzureMachineSpec defines the desired state of AzureMachine
type AzureMachineSpec struct {
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

	// ProviderID is the unique identifier as specified by the cloud provider.
	// +optional
	ProviderID *string `json:"providerID,omitempty"`
}

// AzureMachineStatus defines the observed state of AzureMachine
type AzureMachineStatus struct {
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

	// Addresses is a list of addresses assigned to the machine.
	// This field is copied from the infrastructure provider reference.
	// +optional
	Addresses capiv1.MachineAddresses `json:"addresses,omitempty"`

	// Ready is true when the provider resource is ready.
	// +optional
	Ready bool `json:"ready"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AzureMachine is the Schema for the azuremachines API
type AzureMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureMachineSpec   `json:"spec,omitempty"`
	Status AzureMachineStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AzureMachineList contains a list of AzureMachine
type AzureMachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureMachine `json:"items"`
}

func init() { // nolint: gochecknoinits
	SchemeBuilder.Register(&AzureMachine{}, &AzureMachineList{})
}
