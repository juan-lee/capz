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

package v1alpha2

// APIEndpoint represents a reachable Kubernetes API endpoint.
type APIEndpoint struct {
	// Host is the hostname on which the API server is serving.
	Host string `json:"host,omitempty"`

	// Port is the port on which the API server is serving.
	Port int `json:"port,omitempty"`
}

// ResourceGroup
type ResourceGroup struct {
	// Name
	Name string `json:"name,omitempty"`

	// SubscriptionID
	SubscriptionID string `json:"subscriptionID,omitempty"`

	// Region
	Region string `json:"region,omitempty"`
}

// Network
type Network struct {
	// VirtualNetwork
	VirtualNetwork VirtualNetwork `json:"vnet,omitempty"`

	// Subnets
	Subnets []Subnet `json:"subnets"`

	// Subnets
	SecurityGroups []SecurityGroup `json:"securityGroups"`

	// RouteTable
	RouteTable RouteTable `json:"routeTable,omitempty"`

	// LoadBalancer
	LoadBalancer LoadBalancer `json:"loadBalancer,omitempty"`
}

// VirtualNetwork
type VirtualNetwork struct {
	// Name
	Name string `json:"name,omitempty"`

	// CIDRs
	CIDRs []string `json:"cidrs"`
}

// Subnet
type Subnet struct {
	// Name
	Name string `json:"name,omitempty"`

	// VirtualNetwork
	VirtualNetwork string `json:"vnet,omitempty"`

	// RouteTable
	RouteTable string `json:"routeTable,omitempty"`

	// SecurityGroup
	SecurityGroup string `json:"securityGroup,omitempty"`

	// CIDR
	CIDR string `json:"cidr,omitempty"`
}

// RouteTable
type RouteTable struct {
	// Name
	Name string `json:"name,omitempty"`
}

// SecurityGroup
type SecurityGroup struct {
	// Name
	Name string `json:"name,omitempty"`
}

// LoadBalancer
type LoadBalancer struct {
	// Name
	Name string `json:"name,omitempty"`
}
