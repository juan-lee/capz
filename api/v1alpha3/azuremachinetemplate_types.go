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
)

// AzureMachineTemplateResource defines the desired state of AzureMachineTemplate
type AzureMachineTemplateResource struct {
	Spec AzureMachineSpec `json:"spec"`
}

// AzureMachineTemplateSpec defines the desired state of AzureMachineTemplate
type AzureMachineTemplateSpec struct {
	Template AzureMachineTemplateResource `json:"template"`
}

// AzureMachineTemplateStatus defines the observed state of AzureMachineTemplate
type AzureMachineTemplateStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true

// AzureMachineTemplate is the Schema for the azuremachinetemplates API
type AzureMachineTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureMachineTemplateSpec   `json:"spec,omitempty"`
	Status AzureMachineTemplateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AzureMachineTemplateList contains a list of AzureMachineTemplate
type AzureMachineTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureMachineTemplate `json:"items"`
}

func init() { // nolint: gochecknoinits
	SchemeBuilder.Register(&AzureMachineTemplate{}, &AzureMachineTemplateList{})
}
