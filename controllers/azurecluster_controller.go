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

package controllers

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/msi/mgmt/2018-11-30/msi"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-06-01/network"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2019-05-01/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/juan-lee/capz/api/v1alpha2"
)

// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azureclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azureclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=clusters;clusters/status,verbs=get;list;watch

// AzureClusterReconciler reconciles a AzureCluster object
type AzureClusterReconciler struct {
	client.Client
	Log logr.Logger
}

func authorizeFromFile(c *autorest.Client) error {
	auth, err := auth.NewAuthorizerFromFileWithResource(azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return err
	}
	c.Authorizer = auth
	if err := c.AddToUserAgent("capz"); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.AzureCluster{}).
		Complete(r)
}

func (r *AzureClusterReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	instance := &v1alpha2.AzureCluster{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		r.Log.Error(err, "Error fetching AzureCluster")
		return ctrl.Result{}, nil
	}
	if err := r.reconcileEnvironment(ctx, instance); err != nil {
		r.Log.Error(err, "Error reconciling environment")
		return ctrl.Result{}, nil
	}
	if err := r.reconcileNetwork(ctx, instance); err != nil {
		r.Log.Error(err, "Error reconciling network")
		return ctrl.Result{}, nil
	}
	instance.Status.Ready = true
	err = r.Status().Update(ctx, instance)
	if err != nil {
		r.Log.Error(err, "Error updating status")
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AzureClusterReconciler) reconcileEnvironment(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	if err := r.reconcileResourceGroup(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileIdentity(ctx, instance); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileResourceGroup(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	groups := resources.NewGroupsClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&groups.Client)
	if err != nil {
		r.Log.Error(err, "auth fail")
		return err
	}
	group, err := groups.Get(ctx, instance.Spec.ResourceGroup.Name)
	if err != nil && !NotFound(err) {
		return err
	}
	r.Log.Info("Found resource group", "group", group)
	group.Name = &instance.Spec.ResourceGroup.Name
	group.Location = &instance.Spec.ResourceGroup.Region
	clearState(&group)
	group, err = groups.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, group)
	if err != nil {
		return err
	}
	r.Log.Info("Updated resource group", "group", group)
	return nil
}

func (r *AzureClusterReconciler) reconcileIdentity(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	identities := msi.NewUserAssignedIdentitiesClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&identities.Client)
	if err != nil {
		r.Log.Error(err, "auth fail")
		return err
	}
	uid, err := identities.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.ResourceGroup.Name)
	if err != nil && !NotFound(err) {
		return err
	}
	r.Log.Info("Found user assigned managed identity", "uid", uid)
	uid.Location = &instance.Spec.ResourceGroup.Region
	r.Log.Info("Updating user assigned managed identity", "uid", uid)
	uid, err = identities.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.ResourceGroup.Name, uid)
	if err != nil {
		return err
	}
	r.Log.Info("Updated user assigned managed identity", "uid", uid)
	return nil
}

func (r *AzureClusterReconciler) reconcileNetwork(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	if err := r.reconcileRouteTable(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileSecurityGroups(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileVirtualNetwork(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileSubnets(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileAPIEndpoint(ctx, instance); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileRouteTable(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	c := network.NewRouteTablesClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return err
	}
	rt, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.RouteTable.Name, "")
	if err != nil && !NotFound(err) {
		return err
	}
	r.Log.Info("Found route table", "rt", rt)
	rt.Location = &instance.Spec.ResourceGroup.Region
	r.Log.Info("Updating route table", "rt", rt)
	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.RouteTable.Name, rt)
	if err != nil {
		return err
	}
	if err := future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return err
	}
	rt, err = future.Result(c)
	if err != nil {
		return err
	}
	r.Log.Info("Updated route table", "rt", rt)
	return nil

}

func (r *AzureClusterReconciler) reconcileSecurityGroups(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	c := network.NewSecurityGroupsClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return err
	}
	for n := range instance.Spec.Network.SecurityGroups {
		sg, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.SecurityGroups[n].Name, "")
		if err != nil && !NotFound(err) {
			return err
		}
		r.Log.Info("Found security group", "sg", sg)
		sg.Location = &instance.Spec.ResourceGroup.Region
		// TODO(jpang): fix this magic
		if instance.Spec.Network.SecurityGroups[n].Name == "controlplane" {
			addInboundTCPAllowRule(&sg, 150, "allow_ssh", "22")
			addInboundTCPAllowRule(&sg, 151, "allow_apiserver", "6443")
		}
		r.Log.Info("Updating security group", "sg", sg)
		future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.SecurityGroups[n].Name, sg)
		if err != nil {
			return err
		}
		if err := future.WaitForCompletionRef(ctx, c.Client); err != nil {
			return err
		}
		sg, err = future.Result(c)
		if err != nil {
			return err
		}
		r.Log.Info("Updated security group", "sg", sg)
	}
	return nil
}

func addInboundTCPAllowRule(sg *network.SecurityGroup, priority int, name, port string) {
	if sg.SecurityGroupPropertiesFormat == nil {
		sg.SecurityGroupPropertiesFormat = &network.SecurityGroupPropertiesFormat{}
	}

	if sg.SecurityGroupPropertiesFormat.SecurityRules == nil {
		sg.SecurityGroupPropertiesFormat.SecurityRules = &[]network.SecurityRule{}
	}

	found := false
	for _, rule := range *sg.SecurityGroupPropertiesFormat.SecurityRules {
		if *rule.Name != name {
			continue
		}
		rule.Protocol = network.SecurityRuleProtocolTCP
		rule.SourceAddressPrefix = to.StringPtr("*")
		rule.SourcePortRange = to.StringPtr("*")
		rule.DestinationAddressPrefix = to.StringPtr("*")
		rule.DestinationPortRange = &port
		rule.Access = network.SecurityRuleAccessAllow
		rule.Direction = network.SecurityRuleDirectionInbound
		rule.Priority = to.Int32Ptr(int32(priority))
		found = true
	}

	if !found {
		*sg.SecurityGroupPropertiesFormat.SecurityRules = append(
			*sg.SecurityGroupPropertiesFormat.SecurityRules,
			network.SecurityRule{
				Name: &name,
				SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
					Protocol:                 network.SecurityRuleProtocolTCP,
					SourceAddressPrefix:      to.StringPtr("*"),
					SourcePortRange:          to.StringPtr("*"),
					DestinationAddressPrefix: to.StringPtr("*"),
					DestinationPortRange:     &port,
					Access:                   network.SecurityRuleAccessAllow,
					Direction:                network.SecurityRuleDirectionInbound,
					Priority:                 to.Int32Ptr(int32(priority)),
				},
			},
		)
	}
}

func (r *AzureClusterReconciler) reconcileVirtualNetwork(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	vnets := network.NewVirtualNetworksClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&vnets.Client)
	if err != nil {
		return err
	}

	vnet, err := vnets.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.ResourceGroup.Name, "")
	if err != nil && !NotFound(err) {
		return err
	}
	r.Log.Info("Found virtual network", "vnet", vnet)

	vnet.Name = &instance.Spec.Network.VirtualNetwork.Name
	vnet.Location = &instance.Spec.ResourceGroup.Region
	changed, err := applyVNETChanges(instance.Spec.Network.VirtualNetwork, &vnet)
	if err != nil {
		return err
	}

	if changed {
		r.Log.Info("Updating virtual network", "vnet", vnet)
		future, err := vnets.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, *vnet.Name, vnet)
		if err != nil {
			return err
		}
		if err := future.WaitForCompletionRef(ctx, vnets.Client); err != nil {
			return err
		}
		vnet, err = future.Result(vnets)
		r.Log.Info("Updated virtual network", "vnet", vnet)
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileSubnets(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	for n := range instance.Spec.Network.Subnets {
		rt, err := getRouteTable(ctx, instance.Spec.ResourceGroup.SubscriptionID, instance.Spec.ResourceGroup.Name, instance.Spec.Network.Subnets[n].RouteTable)
		if err != nil {
			return err
		}
		sg, err := getSecurityGroup(ctx, instance.Spec.ResourceGroup.SubscriptionID, instance.Spec.ResourceGroup.Name, instance.Spec.Network.Subnets[n].SecurityGroup)
		if err != nil {
			return err
		}
		c := network.NewSubnetsClient(instance.Spec.ResourceGroup.SubscriptionID)
		err = authorizeFromFile(&c.Client)
		if err != nil {
			return err
		}
		subnet := network.Subnet{SubnetPropertiesFormat: &network.SubnetPropertiesFormat{}}
		for list, err := c.List(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.Subnets[n].VirtualNetwork); list.NotDone(); err = list.NextWithContext(ctx) {
			if err != nil {
				return err
			}
			for _, v := range list.Values() {
				if instance.Spec.Network.Subnets[n].Name == *v.Name {
					subnet = v
					r.Log.Info("Found subnet", "subnet", subnet)
				}
			}
		}
		subnet.RouteTable = rt
		subnet.NetworkSecurityGroup = sg
		changed, err := applySubnetChanges(instance.Spec.Network.Subnets[n], &subnet)
		if err != nil {
			return err
		}
		if changed {
			r.Log.Info("Updating subnet", "subnet", subnet)
			future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.Subnets[n].VirtualNetwork, instance.Spec.Network.Subnets[n].Name, subnet)
			if err := future.WaitForCompletionRef(ctx, c.Client); err != nil {
				return err
			}
			subnet, err = future.Result(c)
			if err != nil {
				return err
			}
			r.Log.Info("Updated subnet", "subnet", subnet)
		}
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileAPIEndpoint(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	if err := r.reconcilePublicIP(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileLoadBalancer(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileLoadBalancerRules(ctx, instance); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) reconcilePublicIP(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	c := network.NewPublicIPAddressesClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return err
	}
	ip, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, "")
	if err != nil && !NotFound(err) {
		return err
	}
	r.Log.Info("Found public ip", "ip", ip)

	ip.Location = &instance.Spec.ResourceGroup.Region
	ip.Sku = &network.PublicIPAddressSku{Name: network.PublicIPAddressSkuNameStandard}
	if ip.PublicIPAddressPropertiesFormat == nil {
		ip.PublicIPAddressPropertiesFormat = &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
			DNSSettings:              &network.PublicIPAddressDNSSettings{},
		}
	}
	ip.DNSSettings.DomainNameLabel = &instance.Spec.ResourceGroup.Name

	r.Log.Info("Updating public ip", "ip", ip)
	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, ip)
	if err != nil {
		return err
	}
	if err := future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return err
	}
	ip, err = future.Result(c)
	if err != nil {
		return err
	}
	r.Log.Info("Updated public ip", "ip", ip)
	if ip.DNSSettings.Fqdn != nil && *ip.DNSSettings.Fqdn != "" {
		found := false
		for n := range instance.Status.APIEndpoints {
			if instance.Status.APIEndpoints[n].Host == *ip.DNSSettings.Fqdn {
				found = true
				break
			}
		}
		if !found {
			r.Log.Info("Updating Status.APIEndpoints", "fqdn", *ip.DNSSettings.Fqdn)
			instance.Status.APIEndpoints = append(instance.Status.APIEndpoints, v1alpha2.APIEndpoint{
				Host: *ip.DNSSettings.Fqdn,
				Port: 6443,
			})
		}
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileLoadBalancer(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	c := network.NewLoadBalancersClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return err
	}
	ip, err := getPublicIP(ctx, instance.Spec.ResourceGroup.SubscriptionID, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name)
	if err != nil {
		return err
	}
	lb, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, "")
	if err != nil && !NotFound(err) {
		return err
	}
	r.Log.Info("Found load balancer", "lb", lb)

	lb.Location = &instance.Spec.ResourceGroup.Region
	lb.Sku = &network.LoadBalancerSku{Name: network.LoadBalancerSkuNameStandard}

	if lb.LoadBalancerPropertiesFormat == nil {
		lb.LoadBalancerPropertiesFormat = &network.LoadBalancerPropertiesFormat{
			BackendAddressPools:      &[]network.BackendAddressPool{},
			FrontendIPConfigurations: &[]network.FrontendIPConfiguration{},
			LoadBalancingRules:       &[]network.LoadBalancingRule{},
			Probes:                   &[]network.Probe{},
			InboundNatRules:          &[]network.InboundNatRule{},
		}
	}

	feConfigName := "frontend"
	found := false
	for _, config := range *lb.FrontendIPConfigurations {
		if *config.Name == feConfigName {
			config.FrontendIPConfigurationPropertiesFormat = makePublicFrontendIPConfig(*ip.ID)
			found = true
		}
	}

	if !found {
		*lb.FrontendIPConfigurations = append(
			*lb.FrontendIPConfigurations,
			network.FrontendIPConfiguration{
				Name:                                    &feConfigName,
				FrontendIPConfigurationPropertiesFormat: makePublicFrontendIPConfig(*ip.ID),
			})
	}

	bePoolName := "backend"
	found = false
	for _, config := range *lb.BackendAddressPools {
		if *config.Name == bePoolName {
			found = true
		}
	}

	if !found {
		*lb.BackendAddressPools = append(
			*lb.BackendAddressPools,
			network.BackendAddressPool{
				Name: &bePoolName,
			})
	}

	// TODO(jpang): hardcoded port
	apiServerProbeName := "https_6443"
	found = false
	for _, config := range *lb.Probes {
		if *config.Name == apiServerProbeName {
			config.ProbePropertiesFormat = makeProbeProperties(6443)
			found = true
		}
	}

	if !found {
		*lb.Probes = append(
			*lb.Probes,
			network.Probe{
				Name:                  &apiServerProbeName,
				ProbePropertiesFormat: makeProbeProperties(6443),
			})
	}

	r.Log.Info("Updating load balancer", "lb", lb)
	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, lb)
	if err != nil {
		return err
	}
	if err := future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return err
	}
	lb, err = future.Result(c)
	if err != nil {
		return err
	}
	r.Log.Info("Updated load balancer", "lb", lb)
	return nil
}

func (r *AzureClusterReconciler) reconcileLoadBalancerRules(ctx context.Context, instance *v1alpha2.AzureCluster) error {
	c := network.NewLoadBalancersClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return err
	}
	lb, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, "")
	if err != nil {
		return err
	}
	r.Log.Info("Found load balancer", "lb", lb)

	apiServerRuleName := "https_6443"
	found := false
	for _, config := range *lb.LoadBalancingRules {
		if *config.Name == apiServerRuleName {
			config.LoadBalancingRulePropertiesFormat = makeRule(
				6443,
				6443,
				findFrontendIPConfigurationID(&lb, "frontend"),
				findBackendAddressPoolID(&lb, "backend"),
				findProbeID(&lb, "https_6443"),
			)
			found = true
		}
	}

	if !found {
		*lb.LoadBalancerPropertiesFormat.LoadBalancingRules = append(
			*lb.LoadBalancerPropertiesFormat.LoadBalancingRules,
			network.LoadBalancingRule{
				Name: &apiServerRuleName,
				LoadBalancingRulePropertiesFormat: makeRule(
					6443,
					6443,
					findFrontendIPConfigurationID(&lb, "frontend"),
					findBackendAddressPoolID(&lb, "backend"),
					findProbeID(&lb, "https_6443"),
				),
			})
	}

	natPoolName := "ssh"
	found = false
	for _, config := range *lb.InboundNatPools {
		if *config.Name == natPoolName {
			config.InboundNatPoolPropertiesFormat = makeNATPool(
				50000,
				50009,
				22,
				findFrontendIPConfigurationID(&lb, "frontend"),
			)
			found = true
		}
	}

	if !found {
		*lb.LoadBalancerPropertiesFormat.InboundNatPools = append(
			*lb.LoadBalancerPropertiesFormat.InboundNatPools,
			network.InboundNatPool{
				Name: &natPoolName,
				InboundNatPoolPropertiesFormat: makeNATPool(
					50000,
					50009,
					22,
					findFrontendIPConfigurationID(&lb, "frontend"),
				),
			})
	}

	r.Log.Info("Updating load balancer rules", "lb", lb)
	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, lb)
	if err != nil {
		return err
	}
	if err := future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return err
	}
	lb, err = future.Result(c)
	if err != nil {
		return err
	}
	r.Log.Info("Updated load balancer rules", "lb", lb)
	return nil
}

func makeRule(frontPort, backPort int, fe, be, pr string) *network.LoadBalancingRulePropertiesFormat {
	return &network.LoadBalancingRulePropertiesFormat{
		Protocol:                network.TransportProtocolTCP,
		FrontendPort:            to.Int32Ptr(int32(frontPort)),
		BackendPort:             to.Int32Ptr(int32(backPort)),
		IdleTimeoutInMinutes:    to.Int32Ptr(4),
		EnableFloatingIP:        to.BoolPtr(false),
		EnableTCPReset:          to.BoolPtr(true),
		LoadDistribution:        network.LoadDistributionDefault,
		FrontendIPConfiguration: &network.SubResource{ID: &fe},
		BackendAddressPool:      &network.SubResource{ID: &be},
		Probe:                   &network.SubResource{ID: &pr},
	}
}

func makeNATPool(frontPortStart, frontPortEnd, backPort int, fe string) *network.InboundNatPoolPropertiesFormat {
	return &network.InboundNatPoolPropertiesFormat{
		FrontendIPConfiguration: &network.SubResource{ID: &fe},
		Protocol:                network.TransportProtocolTCP,
		FrontendPortRangeStart:  to.Int32Ptr(int32(frontPortStart)),
		FrontendPortRangeEnd:    to.Int32Ptr(int32(frontPortEnd)),
		BackendPort:             to.Int32Ptr(int32(backPort)),
		IdleTimeoutInMinutes:    to.Int32Ptr(4),
		EnableFloatingIP:        to.BoolPtr(false),
		EnableTCPReset:          to.BoolPtr(true),
	}
}

func findFrontendIPConfigurationID(lb *network.LoadBalancer, name string) string {
	for _, config := range *lb.LoadBalancerPropertiesFormat.FrontendIPConfigurations {
		if *config.Name == name {
			return *config.ID
		}
	}
	return ""
}

func findBackendAddressPoolID(lb *network.LoadBalancer, name string) string {
	for _, config := range *lb.LoadBalancerPropertiesFormat.BackendAddressPools {
		if *config.Name == name {
			return *config.ID
		}
	}
	return ""
}

func findProbeID(lb *network.LoadBalancer, name string) string {
	for _, config := range *lb.LoadBalancerPropertiesFormat.Probes {
		if *config.Name == name {
			return *config.ID
		}
	}
	return ""
}

func makeProbeProperties(port int) *network.ProbePropertiesFormat {
	return &network.ProbePropertiesFormat{
		Protocol:          network.ProbeProtocolHTTPS,
		Port:              to.Int32Ptr(int32(port)),
		IntervalInSeconds: to.Int32Ptr(5),
		NumberOfProbes:    to.Int32Ptr(2),
		RequestPath:       to.StringPtr("/healthz"),
	}
}

func makePublicFrontendIPConfig(publicIPAddressID string) *network.FrontendIPConfigurationPropertiesFormat {
	return &network.FrontendIPConfigurationPropertiesFormat{
		PublicIPAddress: &network.PublicIPAddress{ID: &publicIPAddressID},
	}
}

func applySubnetChanges(spec v1alpha2.Subnet, subnet *network.Subnet) (bool, error) {
	changed := false
	if subnet.AddressPrefix == nil || spec.CIDR != *subnet.AddressPrefix {
		changed = true
		subnet.AddressPrefix = &spec.CIDR
	}
	return changed, nil
}

func getPublicIP(ctx context.Context, subID, rg, name string) (*network.PublicIPAddress, error) {
	c := network.NewPublicIPAddressesClient(subID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return &network.PublicIPAddress{}, err
	}
	ip, err := c.Get(ctx, rg, name, "")
	if err != nil && !NotFound(err) {
		return &network.PublicIPAddress{}, err
	}
	return &ip, nil
}

func getSecurityGroup(ctx context.Context, subID, rg, name string) (*network.SecurityGroup, error) {
	c := network.NewSecurityGroupsClient(subID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return &network.SecurityGroup{}, err
	}
	sg, err := c.Get(ctx, rg, name, "")
	if err != nil && !NotFound(err) {
		return &network.SecurityGroup{}, err
	}
	return &sg, nil
}

func getRouteTable(ctx context.Context, subID, rg, name string) (*network.RouteTable, error) {
	c := network.NewRouteTablesClient(subID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return &network.RouteTable{}, err
	}
	rt, err := c.Get(ctx, rg, name, "")
	if err != nil && !NotFound(err) {
		return &network.RouteTable{}, err
	}
	return &rt, nil
}

func applyVNETChanges(spec v1alpha2.VirtualNetwork, vnet *network.VirtualNetwork) (bool, error) {
	changed := false
	if vnet.VirtualNetworkPropertiesFormat == nil {
		vnet.VirtualNetworkPropertiesFormat = &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &[]string{},
			},
		}
	}
	addrSpace := vnet.VirtualNetworkPropertiesFormat.AddressSpace
	for n := range spec.CIDRs {
		found := false
		for i := range *addrSpace.AddressPrefixes {
			if spec.CIDRs[n] == (*addrSpace.AddressPrefixes)[i] {
				found = true
				break
			}
		}
		if !found {
			*addrSpace.AddressPrefixes = append(*addrSpace.AddressPrefixes, spec.CIDRs[n])
			changed = true
		}
	}
	return changed, nil
}

func clearState(group *resources.Group) {
	if group.Properties != nil {
		group.Properties.ProvisioningState = nil
	}
}

func NotFound(e error) bool {
	if err, ok := e.(autorest.DetailedError); ok && err.StatusCode == 404 {
		return true
	}
	return false
}
