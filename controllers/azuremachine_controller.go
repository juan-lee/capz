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

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-06-01/network"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	capiv1alpha2 "sigs.k8s.io/cluster-api/api/v1alpha2"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/juan-lee/capz/api/v1alpha2"
)

// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azuremachines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azuremachines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machines;machines/status,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch

// AzureMachineReconciler reconciles a AzureMachine object
type AzureMachineReconciler struct {
	client.Client
	Log logr.Logger
}

type machineContext struct {
	Client client.Client
	*v1alpha2.AzureMachine
	AzureCluster *v1alpha2.AzureCluster
	Machine      *capiv1alpha2.Machine
	Cluster      *capiv1alpha2.Cluster
	patchHelper  *patch.Helper
}

type virtualMachineScaleSet struct {
	*compute.VirtualMachineScaleSet
}

func (m *machineContext) Close(ctx context.Context) error {
	return m.patchHelper.Patch(ctx, m.AzureMachine)
}

func (m *machineContext) SubnetID(cidr string) string {
	c := network.NewSubnetsClient(m.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return ""
	}
	ctx := context.Background()
	for list, err := c.List(ctx, m.Spec.ResourceGroup.Name, m.AzureCluster.Spec.Network.VirtualNetwork.Name); list.NotDone(); err = list.NextWithContext(ctx) {
		if err != nil {
			return ""
		}
		for _, v := range list.Values() {
			if cidr == *v.AddressPrefix {
				return *v.ID
			}
		}
	}
	return ""
}

func (m *machineContext) BackendPoolIDs(lbname string) []string {
	c := network.NewLoadBalancersClient(m.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return nil
	}
	lb, err := c.Get(context.Background(), m.Spec.ResourceGroup.Name, m.AzureCluster.Spec.Network.LoadBalancer.Name, "")
	if err != nil && !notFound(err) {
		return nil
	}
	var result []string
	for n := range *lb.BackendAddressPools {
		result = append(result, *(*lb.BackendAddressPools)[n].ID)
	}
	return result
}

func (m *machineContext) InboundNatPoolIDs(lbname string) []string {
	c := network.NewLoadBalancersClient(m.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&c.Client)
	if err != nil {
		return nil
	}
	lb, err := c.Get(context.Background(), m.Spec.ResourceGroup.Name, m.AzureCluster.Spec.Network.LoadBalancer.Name, "")
	if err != nil && !notFound(err) {
		return nil
	}
	var result []string
	for n := range *lb.InboundNatPools {
		result = append(result, *(*lb.InboundNatPools)[n].ID)
	}
	return result
}

func (r *AzureMachineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.AzureMachine{}).
		Watches(
			&source.Kind{Type: &capiv1alpha2.Machine{}},
			&handler.EnqueueRequestsFromMapFunc{
				ToRequests: util.MachineToInfrastructureMapFunc(v1alpha2.GroupVersion.WithKind("AzureMachine")),
			},
		).
		Watches(
			&source.Kind{Type: &v1alpha2.AzureCluster{}},
			&handler.EnqueueRequestsFromMapFunc{ToRequests: handler.ToRequestsFunc(r.AzureClusterToAzureMachines)},
		).
		Complete(r)
}

func (r *AzureMachineReconciler) Reconcile(req ctrl.Request) (_ ctrl.Result, reterr error) {
	_ = context.Background()
	log := r.Log.WithValues("azuremachine", req.NamespacedName)

	ctx := context.Background()
	machine, err := r.getMachineContext(ctx, req)
	if err != nil {
		log.Info("Error creating machine context [%+v]", "err", err)
		return ctrl.Result{}, nil
	}

	if machine.Status.ErrorReason != nil || machine.Status.ErrorMessage != nil {
		log.Info("Error state detected, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// TODO(jpang): enable once delete is implemented
	// if !util.Contains(machine.Finalizers, v1alpha2.MachineFinalizer) {
	// 	machine.Finalizers = append(machine.Finalizers, v1alpha2.MachineFinalizer)
	// }

	if !machine.Cluster.Status.InfrastructureReady {
		log.Info("Cluster infrastructure is not ready yet")
		return ctrl.Result{}, nil
	}

	// Make sure bootstrap data is available and populated.
	if machine.Machine.Spec.Bootstrap.Data == nil {
		log.Info("Bootstrap data is not yet available")
		return ctrl.Result{}, nil
	}

	defer func() {
		if err := machine.Close(ctx); err != nil && reterr == nil {
			reterr = err
			log.Error(err, "Error closing machine context")
		}
	}()

	if err := r.reconcileMachine(ctx, machine); err != nil {
		log.Error(err, "Error reconciling machine")
		return ctrl.Result{}, nil
	}
	if err := r.reconcileMachineInstance(ctx, machine); err != nil {
		log.Error(err, "Error reconciling machine instance")
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AzureMachineReconciler) getMachineContext(ctx context.Context, req ctrl.Request) (*machineContext, error) {
	log := r.Log.WithValues("azuremachine", req.NamespacedName)
	instance := &v1alpha2.AzureMachine{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		return nil, err
	}

	machine, err := util.GetOwnerMachine(ctx, r.Client, instance.ObjectMeta)
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, errors.New("Machine Controller has not yet set OwnerRef")
	}

	cluster, err := util.GetClusterFromMetadata(ctx, r.Client, machine.ObjectMeta)
	if err != nil {
		log.Info("Machine is missing cluster label or cluster does not exist")
		return nil, err
	}

	azureCluster := &v1alpha2.AzureCluster{}
	azureClusterName := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      cluster.Spec.InfrastructureRef.Name,
	}
	if err := r.Client.Get(ctx, azureClusterName, azureCluster); err != nil {
		log.Info("AzureCluster is not available yet")
		return nil, err
	}

	helper, err := patch.NewHelper(instance, r.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to init patch helper %w", err)
	}
	return &machineContext{
		Client:       r.Client,
		AzureMachine: instance,
		AzureCluster: azureCluster,
		Machine:      machine,
		Cluster:      cluster,
		patchHelper:  helper,
	}, nil
}

func (r *AzureMachineReconciler) reconcileMachine(ctx context.Context, machine *machineContext) error {
	scalesets := compute.NewVirtualMachineScaleSetsClient(machine.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&scalesets.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	scaleset, err := scalesets.Get(ctx, machine.Spec.ResourceGroup.Name, machine.Spec.Name)
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get vm scale set [%w]", err)
	}

	applyMachineSpec(machine, &scaleset)

	future, err := scalesets.CreateOrUpdate(ctx, machine.Spec.ResourceGroup.Name, machine.Spec.Name, scaleset)
	if err != nil {
		return fmt.Errorf("failed to update vm scale set [%w]\n%+v", err, scaleset)
	}
	if err := future.WaitForCompletionRef(ctx, scalesets.Client); err != nil {
		return fmt.Errorf("failed to wait for update vm scale set [%w]\n%+v", err, scaleset)
	}
	scaleset, err = future.Result(scalesets)
	if err != nil {
		return fmt.Errorf("failed to get result for update vm scale set [%w]\n%+v", err, scaleset)
	}
	return nil
}

func (r *AzureMachineReconciler) reconcileMachineInstance(ctx context.Context, machine *machineContext) error {
	log := r.Log.WithValues("azuremachine", fmt.Sprintf("%s/%s", machine.Namespace, machine.Name))

	vms := compute.NewVirtualMachineScaleSetVMsClient(machine.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&vms.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	for list, err := vms.List(ctx, machine.Spec.ResourceGroup.Name, machine.Spec.Name, "", "", ""); list.NotDone(); err = list.NextWithContext(ctx) {
		if err != nil {
			return fmt.Errorf("failed to list vm scale sets [%w]", err)
		}
		for _, v := range list.Values() {
			machine.Spec.ProviderID = to.StringPtr(fmt.Sprintf("azure://%s", *v.ID))
			machine.Status.Ready = true
			log.Info("Setting ProviderID and Ready", "machine.Spec.ProviderID", *machine.Spec.ProviderID, "machine.Status.Ready", machine.Status.Ready)
		}
	}
	return nil
}

// AzureClusterToAzureMachine is a handler.ToRequestsFunc to be used to enqeue
// requests for reconciliation of AzureMachines.
func (r *AzureMachineReconciler) AzureClusterToAzureMachines(o handler.MapObject) []ctrl.Request {
	result := []ctrl.Request{}
	c, ok := o.Object.(*v1alpha2.AzureCluster)
	if !ok {
		r.Log.Error(errors.Errorf("expected a AzureCluster but got a %T", o.Object), "failed to get AzureMachine for AzureCluster")
		return nil
	}
	log := r.Log.WithValues("AzureCluster", c.Name, "Namespace", c.Namespace)

	cluster, err := util.GetOwnerCluster(context.TODO(), r.Client, c.ObjectMeta)
	switch {
	case apierrors.IsNotFound(err) || cluster == nil:
		return result
	case err != nil:
		log.Error(err, "failed to get owning cluster")
		return result
	}

	labels := map[string]string{capiv1alpha2.MachineClusterLabelName: cluster.Name}
	machineList := &capiv1alpha2.MachineList{}
	if err := r.List(context.TODO(), machineList, client.InNamespace(c.Namespace), client.MatchingLabels(labels)); err != nil {
		log.Error(err, "failed to list Machines")
		return nil
	}
	for _, m := range machineList.Items {
		if m.Spec.InfrastructureRef.Name == "" {
			continue
		}
		name := client.ObjectKey{Namespace: m.Namespace, Name: m.Spec.InfrastructureRef.Name}
		result = append(result, ctrl.Request{NamespacedName: name})
	}

	return result
}

func applyMachineSpec(machine *machineContext, in *compute.VirtualMachineScaleSet) {
	vmss := newVMSS(in)
	vmss.SetName(machine.Spec.Name)
	vmss.SetRegion(&machine.Spec.ResourceGroup)
	vmss.SetSKU(machine.Spec.SKU)
	// TODO(jpang): hardcode for now
	vmss.SetCapacity(1)
	vmss.SetPrefix(machine.Spec.Name)
	vmss.SetCustomData(*machine.Machine.Spec.Bootstrap.Data)
	vmss.SetSSHPublicKey(machine.Spec.SSHPublicKey)
	vmss.SetUserAssignedIdentity(&machine.Spec.ResourceGroup)
	vmss.SetOSDiskSize(128)
	vmss.SetSubnet(machine.SubnetID(machine.Spec.Subnet))

	if util.IsControlPlaneMachine(machine.Machine) {
		vmss.SetBackendPools(machine.BackendPoolIDs(machine.AzureCluster.Spec.Network.LoadBalancer.Name))
		vmss.SetInboundNATPools(machine.InboundNatPoolIDs(machine.AzureCluster.Spec.Network.LoadBalancer.Name))
	}
}

func newVMSS(vmss *compute.VirtualMachineScaleSet) *virtualMachineScaleSet {
	if vmss.Sku == nil {
		vmss.Sku = &compute.Sku{}
	}
	if vmss.VirtualMachineScaleSetProperties == nil {
		vmss.VirtualMachineScaleSetProperties = &compute.VirtualMachineScaleSetProperties{
			Overprovision: to.BoolPtr(false),
			UpgradePolicy: &compute.UpgradePolicy{
				Mode: compute.Manual,
			},
			VirtualMachineProfile: &compute.VirtualMachineScaleSetVMProfile{
				Priority: compute.Regular,
				OsProfile: &compute.VirtualMachineScaleSetOSProfile{
					AdminUsername: to.StringPtr("azureuser"),
					LinuxConfiguration: &compute.LinuxConfiguration{
						DisablePasswordAuthentication: to.BoolPtr(true),
						SSH: &compute.SSHConfiguration{
							PublicKeys: &[]compute.SSHPublicKey{},
						},
					},
				},
				DiagnosticsProfile: &compute.DiagnosticsProfile{
					BootDiagnostics: &compute.BootDiagnostics{},
				},
				StorageProfile: &compute.VirtualMachineScaleSetStorageProfile{
					ImageReference: &compute.ImageReference{
						Offer:     to.StringPtr("UbuntuServer"),
						Publisher: to.StringPtr("Canonical"),
						Sku:       to.StringPtr("18.04-LTS"),
						Version:   to.StringPtr("latest"),
					},
					OsDisk: &compute.VirtualMachineScaleSetOSDisk{
						CreateOption: compute.DiskCreateOptionTypesFromImage,
					},
				},
				NetworkProfile: &compute.VirtualMachineScaleSetNetworkProfile{
					NetworkInterfaceConfigurations: &[]compute.VirtualMachineScaleSetNetworkConfiguration{
						{
							Name: to.StringPtr("ipconfig"),
							VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
								Primary:                     to.BoolPtr(true),
								EnableIPForwarding:          to.BoolPtr(true),
								EnableAcceleratedNetworking: to.BoolPtr(true),
								IPConfigurations: &[]compute.VirtualMachineScaleSetIPConfiguration{
									{
										Name: to.StringPtr("ipconfig"),
										VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
											Subnet: &compute.APIEntityReference{},
										},
									},
								},
							},
						},
					},
				},
			},
		}
	}
	if vmss.Identity == nil {
		vmss.Identity = &compute.VirtualMachineScaleSetIdentity{
			UserAssignedIdentities: map[string]*compute.VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue{},
		}
	}
	return &virtualMachineScaleSet{VirtualMachineScaleSet: vmss}
}

func (vmss *virtualMachineScaleSet) SetName(name string) {
	vmss.VirtualMachineScaleSet.Name = &name
}

func (vmss *virtualMachineScaleSet) SetRegion(rg *v1alpha2.ResourceGroup) {
	vmss.VirtualMachineScaleSet.Location = &rg.Region
}

func (vmss *virtualMachineScaleSet) SetSKU(sku string) {
	vmss.Sku.Name = &sku
}

func (vmss *virtualMachineScaleSet) SetCapacity(c int64) {
	vmss.Sku.Capacity = &c
}

func (vmss *virtualMachineScaleSet) SetPrefix(prefix string) {
	vmss.VirtualMachineScaleSet.VirtualMachineProfile.OsProfile.ComputerNamePrefix = &prefix
}

func (vmss *virtualMachineScaleSet) SetCustomData(data string) {
	vmss.VirtualMachineScaleSetProperties.VirtualMachineProfile.OsProfile.CustomData = &data
}

func (vmss *virtualMachineScaleSet) SetSSHPublicKey(pk string) {
	found := false
	for _, key := range *vmss.VirtualMachineProfile.OsProfile.LinuxConfiguration.SSH.PublicKeys {
		if *key.KeyData == pk {
			key.Path = to.StringPtr("/home/azureuser/.ssh/authorized_keys")
			found = true
		}
	}

	if !found {
		*vmss.VirtualMachineProfile.OsProfile.LinuxConfiguration.SSH.PublicKeys = append(
			*vmss.VirtualMachineProfile.OsProfile.LinuxConfiguration.SSH.PublicKeys,
			compute.SSHPublicKey{
				Path:    to.StringPtr("/home/azureuser/.ssh/authorized_keys"),
				KeyData: &pk,
			},
		)
	}
}

func (vmss *virtualMachineScaleSet) SetUserAssignedIdentity(rg *v1alpha2.ResourceGroup) {
	id := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s",
		rg.SubscriptionID,
		rg.Name,
		rg.Name,
	)
	vmss.Identity.Type = compute.ResourceIdentityTypeUserAssigned
	vmss.Identity.UserAssignedIdentities[id] = &compute.VirtualMachineScaleSetIdentityUserAssignedIdentitiesValue{}
}

func (vmss *virtualMachineScaleSet) SetOSDiskSize(sizeGB int) {
	vmss.VirtualMachineScaleSetProperties.VirtualMachineProfile.StorageProfile.OsDisk.DiskSizeGB = to.Int32Ptr(int32(sizeGB))
}

func (vmss *virtualMachineScaleSet) SetSubnet(subnetID string) {
	(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].VirtualMachineScaleSetIPConfigurationProperties.Subnet.ID = &subnetID
}

func (vmss *virtualMachineScaleSet) SetBackendPools(poolIDs []string) {
	var sr []compute.SubResource
	for n := range poolIDs {
		sr = append(sr, compute.SubResource{ID: &poolIDs[n]})
	}
	(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].LoadBalancerBackendAddressPools = &sr
}

func (vmss *virtualMachineScaleSet) SetInboundNATPools(poolIDs []string) {
	var sr []compute.SubResource
	for n := range poolIDs {
		sr = append(sr, compute.SubResource{ID: &poolIDs[n]})
	}
	(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].LoadBalancerInboundNatPools = &sr
}
