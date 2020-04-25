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
	"fmt"

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

	capiv1 "sigs.k8s.io/cluster-api/api/v1alpha3"

	"github.com/juan-lee/capz/api/v1alpha3"
)

const (
	frontendConfigName   = "frontend"
	apiServerPort        = 6443
	sshPort              = 22
	sshPortRangeStart    = 50000
	sshPortRangeEnd      = 50009
	idleTimeoutMinutes   = 4
	probeIntervalSeconds = 5
	probeCount           = 2
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
	a, err := auth.NewAuthorizerFromFileWithResource(azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return err
	}
	c.Authorizer = a
	if err := c.AddToUserAgent("capz"); err != nil {
		return err
	}
	return nil
}

// SetupWithManager performs manager setup.
func (r *AzureClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha3.AzureCluster{}).
		Complete(r)
}

// Reconcile reconciles an AzureCluster instance.
func (r *AzureClusterReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("azurecluster", req.NamespacedName)
	ctx := context.Background()
	instance := &v1alpha3.AzureCluster{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		log.Info("Error fetching AzureCluster", "err", err)
		return ctrl.Result{}, nil
	}
	if err = r.reconcileEnvironment(ctx, instance); err != nil {
		log.Info("Error reconciling environment", "err", err)
		return ctrl.Result{}, nil
	}
	if err = r.reconcileNetwork(ctx, instance); err != nil {
		log.Info("Error reconciling network", "err", err)
		return ctrl.Result{}, nil
	}
	instance.Status.Ready = true
	err = r.Status().Update(ctx, instance)
	if err != nil {
		log.Info("Error updating status [%+v]", "err", err)
		return ctrl.Result{}, nil
	}
	err = r.Update(ctx, instance)
	if err != nil {
		log.Info("Error updating [%+v]", "err", err)
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AzureClusterReconciler) reconcileEnvironment(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	if err := r.reconcileResourceGroup(ctx, instance); err != nil {
		return err
	}
	if err := r.reconcileIdentity(ctx, instance); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileResourceGroup(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	groups := resources.NewGroupsClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&groups.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	group, err := groups.Get(ctx, instance.Spec.ResourceGroup.Name)
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get resource group [%w]", err)
	}

	group.Name = &instance.Spec.ResourceGroup.Name
	group.Location = &instance.Spec.ResourceGroup.Region
	clearState(&group)

	group, err = groups.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, group)
	if err != nil {
		return fmt.Errorf("failed to update resource group %w\n%+v", err, group)
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileIdentity(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	identities := msi.NewUserAssignedIdentitiesClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&identities.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	uid, err := identities.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.ResourceGroup.Name)
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get identity [%w]", err)
	}

	uid.Location = &instance.Spec.ResourceGroup.Region

	uid, err = identities.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.ResourceGroup.Name, uid)
	if err != nil {
		return fmt.Errorf("failed to update identity %w\n%+v", err, uid)
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileNetwork(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	log := r.Log.WithValues("azurecluster", fmt.Sprintf("%s/%s", instance.Namespace, instance.Name)).
		WithValues("resourceGroup", instance.Spec.ResourceGroup.Name)
	log.Info("Reconciling route table")
	if err := r.reconcileRouteTable(ctx, instance); err != nil {
		return err
	}
	log.Info("Reconciling security groups")
	if err := r.reconcileSecurityGroups(ctx, instance); err != nil {
		return err
	}
	log.Info("Reconciling virtual network")
	if err := r.reconcileVirtualNetwork(ctx, instance); err != nil {
		return err
	}
	log.Info("Reconciling subnets")
	if err := r.reconcileSubnets(ctx, instance); err != nil {
		return err
	}
	log.Info("Reconciling control plane endpoint")
	if err := r.reconcileAPIEndpoint(ctx, instance); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileRouteTable(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	c := network.NewRouteTablesClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	rt, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.RouteTable.Name, "")
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get route table [%w]", err)
	}

	rt.Location = &instance.Spec.ResourceGroup.Region

	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.RouteTable.Name, rt)
	if err != nil {
		return fmt.Errorf("failed to update route table %w\n%+v", err, rt)
	}
	if err = future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return fmt.Errorf("failed to wait for route table update [%w]", err)
	}
	rt, err = future.Result(c)
	if err != nil {
		return fmt.Errorf("failed to get route table update result [%w]", err)
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileSecurityGroups(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	c := network.NewSecurityGroupsClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	for n := range instance.Spec.Network.SecurityGroups {
		sg, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.SecurityGroups[n].Name, "")
		if err != nil && !notFound(err) {
			return fmt.Errorf("failed to get security group [%w]", err)
		}

		sg.Location = &instance.Spec.ResourceGroup.Region
		// TODO(jpang): fix this magic
		if instance.Spec.Network.SecurityGroups[n].Name == "controlplane" {
			addInboundTCPAllowRule(&sg, 150, "allow_ssh", "22")
			addInboundTCPAllowRule(&sg, 151, "allow_apiserver", "6443")
		}

		future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.SecurityGroups[n].Name, sg)
		if err != nil {
			return fmt.Errorf("failed to update security group %w\n%+v", err, sg)
		}
		if err = future.WaitForCompletionRef(ctx, c.Client); err != nil {
			return fmt.Errorf("failed to wait for update security group %w", err)
		}
		sg, err = future.Result(c)
		if err != nil {
			return fmt.Errorf("failed to get result for update security group %w", err)
		}
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

func (r *AzureClusterReconciler) reconcileVirtualNetwork(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	vnets := network.NewVirtualNetworksClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&vnets.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	vnet, err := vnets.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.ResourceGroup.Name, "")
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get virtual network [%w]", err)
	}

	vnet.Name = &instance.Spec.Network.VirtualNetwork.Name
	vnet.Location = &instance.Spec.ResourceGroup.Region
	changed := applyVNETChanges(instance.Spec.Network.VirtualNetwork, &vnet)
	if changed {
		future, err := vnets.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, *vnet.Name, vnet)
		if err != nil {
			return fmt.Errorf("failed to update virtual network [%w]\n%+v", err, vnet)
		}
		if err = future.WaitForCompletionRef(ctx, vnets.Client); err != nil {
			return fmt.Errorf("failed to wait for update virtual network [%w]", err)
		}
		if vnet, err = future.Result(vnets); err != nil {
			return fmt.Errorf("failed to get result for update virtual network [%w]", err)
		}
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileSubnets(ctx context.Context, ac *v1alpha3.AzureCluster) error {
	for n := range ac.Spec.Network.Subnets {
		rt, err := getRouteTable(ctx, &ac.Spec.ResourceGroup, ac.Spec.Network.Subnets[n].RouteTable)
		if err != nil {
			return fmt.Errorf("failed to get route table [%w]", err)
		}
		sg, err := getSecurityGroup(ctx, &ac.Spec.ResourceGroup, ac.Spec.Network.Subnets[n].SecurityGroup)
		if err != nil {
			return fmt.Errorf("failed to get security group [%w]", err)
		}

		c := network.NewSubnetsClient(ac.Spec.ResourceGroup.SubscriptionID)
		err = authorizeFromFile(&c.Client)
		if err != nil {
			return fmt.Errorf("failed to auth [%w]", err)
		}

		subnet := network.Subnet{SubnetPropertiesFormat: &network.SubnetPropertiesFormat{}}
		for list, err := c.List(
			ctx, ac.Spec.ResourceGroup.Name,
			ac.Spec.Network.Subnets[n].VirtualNetwork,
		); list.NotDone(); err = list.NextWithContext(ctx) {
			if err != nil {
				return fmt.Errorf("failed to list subnets [%w]", err)
			}
			for _, v := range list.Values() {
				if ac.Spec.Network.Subnets[n].Name == *v.Name {
					subnet = v
				}
			}
		}

		subnet.RouteTable = rt
		subnet.NetworkSecurityGroup = sg
		changed := applySubnetChanges(&ac.Spec.Network.Subnets[n], &subnet)
		if changed {
			future, err := c.CreateOrUpdate(
				ctx,
				ac.Spec.ResourceGroup.Name,
				ac.Spec.Network.Subnets[n].VirtualNetwork,
				ac.Spec.Network.Subnets[n].Name,
				subnet,
			)
			if err != nil {
				return fmt.Errorf("failed to update subnet [%w]", err)
			}
			if err = future.WaitForCompletionRef(ctx, c.Client); err != nil {
				return fmt.Errorf("failed to wait for update subnet [%w]", err)
			}
			subnet, err = future.Result(c)
			if err != nil {
				return fmt.Errorf("failed to get result for update subnet [%w]", err)
			}
		}
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileAPIEndpoint(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	log := r.Log.WithValues("azurecluster", fmt.Sprintf("%s/%s", instance.Namespace, instance.Name)).
		WithValues("apiEndpoint", instance.Spec.ResourceGroup.Name)
	log.Info("Reconciling public ip")
	if err := r.reconcilePublicIP(ctx, instance); err != nil {
		return err
	}
	log.Info("Reconciling public load balancer")
	if err := r.reconcileLoadBalancer(ctx, instance); err != nil {
		return err
	}
	log.Info("Reconciling public load balancer rules")
	if err := r.reconcileLoadBalancerRules(ctx, instance); err != nil {
		return err
	}
	return nil
}

func (r *AzureClusterReconciler) reconcilePublicIP(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	log := r.Log.WithValues("azurecluster", fmt.Sprintf("%s/%s", instance.Namespace, instance.Name)).
		WithValues("publicIP", instance.Spec.Network.LoadBalancer.Name)
	c := network.NewPublicIPAddressesClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	ip, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, "")
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get public ip [%w]", err)
	}

	ip.Location = &instance.Spec.ResourceGroup.Region
	ip.Sku = &network.PublicIPAddressSku{Name: network.PublicIPAddressSkuNameStandard}
	if ip.PublicIPAddressPropertiesFormat == nil {
		ip.PublicIPAddressPropertiesFormat = &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
			DNSSettings:              &network.PublicIPAddressDNSSettings{},
		}
	}
	ip.DNSSettings.DomainNameLabel = &instance.Spec.ResourceGroup.Name

	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, ip)
	if err != nil {
		return fmt.Errorf("failed to update public ip [%w]\n%+v", err, ip)
	}
	if err = future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return fmt.Errorf("failed to wait for update public ip [%w]", err)
	}
	ip, err = future.Result(c)
	if err != nil {
		return fmt.Errorf("failed to get result for update public ip [%w]", err)
	}
	if ip.DNSSettings.Fqdn != nil && *ip.DNSSettings.Fqdn != "" {
		log.Info("Setting Spec.ControlPlaneEndpoint", "fqdn", *ip.DNSSettings.Fqdn)
		instance.Spec.ControlPlaneEndpoint = capiv1.APIEndpoint{
			Host: *ip.DNSSettings.Fqdn,
			Port: 6443,
		}
	}
	return nil
}

// nolint: gocyclo
func (r *AzureClusterReconciler) reconcileLoadBalancer(ctx context.Context, ac *v1alpha3.AzureCluster) error {
	c := network.NewLoadBalancersClient(ac.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}
	ip, err := getPublicIP(ctx, ac.Spec.ResourceGroup.SubscriptionID, ac.Spec.ResourceGroup.Name, ac.Spec.Network.LoadBalancer.Name)
	if err != nil {
		return fmt.Errorf("failed to get public ip [%w]", err)
	}
	lb, err := c.Get(ctx, ac.Spec.ResourceGroup.Name, ac.Spec.Network.LoadBalancer.Name, "")
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get public load balancer [%w]", err)
	}

	lb.Location = &ac.Spec.ResourceGroup.Region
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

	feConfigName := frontendConfigName
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
	apiServerProbeName := fmt.Sprintf("https_%d", 6443)
	found = false
	for _, config := range *lb.Probes {
		if *config.Name == apiServerProbeName {
			config.ProbePropertiesFormat = makeProbeProperties(apiServerPort)
			found = true
		}
	}

	if !found {
		*lb.Probes = append(
			*lb.Probes,
			network.Probe{
				Name:                  &apiServerProbeName,
				ProbePropertiesFormat: makeProbeProperties(apiServerPort),
			})
	}

	future, err := c.CreateOrUpdate(ctx, ac.Spec.ResourceGroup.Name, ac.Spec.Network.LoadBalancer.Name, lb)
	if err != nil {
		return fmt.Errorf("failed to update public load balancer [%w]\n%+v", err, lb)
	}
	if err = future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return fmt.Errorf("failed to wait for update public load balancer [%w]", err)
	}
	lb, err = future.Result(c)
	if err != nil {
		return fmt.Errorf("failed to get result for update public load balancer [%w]", err)
	}
	return nil
}

func (r *AzureClusterReconciler) reconcileLoadBalancerRules(ctx context.Context, instance *v1alpha3.AzureCluster) error {
	c := network.NewLoadBalancersClient(instance.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}
	lb, err := c.Get(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, "")
	if err != nil {
		return fmt.Errorf("failed to get public load balancer [%w]", err)
	}

	apiServerRuleName := fmt.Sprintf("https_%d", 6443)
	found := false
	for _, config := range *lb.LoadBalancingRules {
		if *config.Name == apiServerRuleName {
			config.LoadBalancingRulePropertiesFormat = makeRule(
				apiServerPort,
				apiServerPort,
				findFrontendIPConfigurationID(&lb),
				findBackendAddressPoolID(&lb, "backend"),
				findProbeID(&lb, apiServerRuleName),
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
					apiServerPort,
					apiServerPort,
					findFrontendIPConfigurationID(&lb),
					findBackendAddressPoolID(&lb, "backend"),
					findProbeID(&lb, apiServerRuleName),
				),
			})
	}

	natPoolName := "ssh"
	found = false
	for _, config := range *lb.InboundNatPools {
		if *config.Name == natPoolName {
			config.InboundNatPoolPropertiesFormat = makeNATPool(
				sshPortRangeStart,
				sshPortRangeEnd,
				sshPort,
				findFrontendIPConfigurationID(&lb),
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
					sshPortRangeStart,
					sshPortRangeEnd,
					sshPort,
					findFrontendIPConfigurationID(&lb),
				),
			})
	}

	future, err := c.CreateOrUpdate(ctx, instance.Spec.ResourceGroup.Name, instance.Spec.Network.LoadBalancer.Name, lb)
	if err != nil {
		return fmt.Errorf("failed to update public load balancer [%w]\n%+v", err, lb)
	}
	if err = future.WaitForCompletionRef(ctx, c.Client); err != nil {
		return fmt.Errorf("failed to wait for update public load balancer [%w]", err)
	}
	lb, err = future.Result(c)
	if err != nil {
		return fmt.Errorf("failed to get result for update public load balancer [%w]", err)
	}
	return nil
}

func makeRule(frontPort, backPort int, fe, be, pr string) *network.LoadBalancingRulePropertiesFormat {
	return &network.LoadBalancingRulePropertiesFormat{
		Protocol:                network.TransportProtocolTCP,
		FrontendPort:            to.Int32Ptr(int32(frontPort)),
		BackendPort:             to.Int32Ptr(int32(backPort)),
		IdleTimeoutInMinutes:    to.Int32Ptr(idleTimeoutMinutes),
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
		IdleTimeoutInMinutes:    to.Int32Ptr(idleTimeoutMinutes),
		EnableFloatingIP:        to.BoolPtr(false),
		EnableTCPReset:          to.BoolPtr(true),
	}
}

func findFrontendIPConfigurationID(lb *network.LoadBalancer) string {
	for _, config := range *lb.LoadBalancerPropertiesFormat.FrontendIPConfigurations {
		if *config.Name == frontendConfigName {
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
		IntervalInSeconds: to.Int32Ptr(probeIntervalSeconds),
		NumberOfProbes:    to.Int32Ptr(probeCount),
		RequestPath:       to.StringPtr("/healthz"),
	}
}

func makePublicFrontendIPConfig(publicIPAddressID string) *network.FrontendIPConfigurationPropertiesFormat {
	return &network.FrontendIPConfigurationPropertiesFormat{
		PublicIPAddress: &network.PublicIPAddress{ID: &publicIPAddressID},
	}
}

func applySubnetChanges(spec *v1alpha3.Subnet, subnet *network.Subnet) bool {
	changed := false
	if subnet.AddressPrefix == nil || spec.CIDR != *subnet.AddressPrefix {
		changed = true
		subnet.AddressPrefix = &spec.CIDR
	}
	return changed
}

func getPublicIP(ctx context.Context, subID, rg, name string) (*network.PublicIPAddress, error) {
	c := network.NewPublicIPAddressesClient(subID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return &network.PublicIPAddress{}, err
	}
	ip, err := c.Get(ctx, rg, name, "")
	if err != nil && !notFound(err) {
		return &network.PublicIPAddress{}, err
	}
	return &ip, nil
}

func getSecurityGroup(ctx context.Context, rg *v1alpha3.ResourceGroup, name string) (*network.SecurityGroup, error) {
	c := network.NewSecurityGroupsClient(rg.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return &network.SecurityGroup{}, err
	}
	sg, err := c.Get(ctx, rg.Name, name, "")
	if err != nil && !notFound(err) {
		return &network.SecurityGroup{}, err
	}
	return &sg, nil
}

func getRouteTable(ctx context.Context, rg *v1alpha3.ResourceGroup, name string) (*network.RouteTable, error) {
	c := network.NewRouteTablesClient(rg.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return &network.RouteTable{}, err
	}
	rt, err := c.Get(ctx, rg.Name, name, "")
	if err != nil && !notFound(err) {
		return &network.RouteTable{}, err
	}
	return &rt, nil
}

func applyVNETChanges(spec v1alpha3.VirtualNetwork, vnet *network.VirtualNetwork) bool {
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
	return changed
}

func clearState(group *resources.Group) {
	if group.Properties != nil {
		group.Properties.ProvisioningState = nil
	}
}

func notFound(e error) bool {
	if err, ok := e.(autorest.DetailedError); ok && err.StatusCode == 404 {
		return true
	}
	return false
}
