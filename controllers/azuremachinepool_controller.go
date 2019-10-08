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
	"k8s.io/apimachinery/pkg/runtime/schema"
	capiv1alpha2 "sigs.k8s.io/cluster-api/api/v1alpha2"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/juan-lee/capz/api/v1alpha2"
	infrastructurev1alpha2 "github.com/juan-lee/capz/api/v1alpha2"
)

// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azuremachinepools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azuremachinepools/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machinepools;machinepools/status,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch

// AzureMachinePoolReconciler reconciles a AzureMachinePool object
type AzureMachinePoolReconciler struct {
	client.Client
	Log logr.Logger
}

type machinePoolContext struct {
	Client client.Client
	*v1alpha2.AzureMachinePool
	AzureCluster *v1alpha2.AzureCluster
	MachinePool  *capiv1alpha2.MachinePool
	Cluster      *capiv1alpha2.Cluster
	patchHelper  *patch.Helper
}

func (m *machinePoolContext) Close(ctx context.Context) error {
	return m.patchHelper.Patch(ctx, m.AzureMachinePool)
}

func (m *machinePoolContext) SubnetID(cidr string) string {
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

func (r *AzureMachinePoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infrastructurev1alpha2.AzureMachinePool{}).
		Watches(
			&source.Kind{Type: &capiv1alpha2.MachinePool{}},
			&handler.EnqueueRequestsFromMapFunc{
				ToRequests: r.MachinePoolToInfrastructureMapFunc(v1alpha2.GroupVersion.WithKind("AzureMachinePool")),
			},
		).
		Watches(
			&source.Kind{Type: &v1alpha2.AzureCluster{}},
			&handler.EnqueueRequestsFromMapFunc{ToRequests: handler.ToRequestsFunc(r.AzureClusterToAzureMachinePool)},
		).
		Complete(r)
}

// MachineToInfrastructureMapFunc returns a handler.ToRequestsFunc that watches for
// Machine events and returns reconciliation requests for an infrastructure provider object.
func (r *AzureMachinePoolReconciler) MachinePoolToInfrastructureMapFunc(gvk schema.GroupVersionKind) handler.ToRequestsFunc {
	return func(o handler.MapObject) []reconcile.Request {
		m, ok := o.Object.(*capiv1alpha2.MachinePool)
		if !ok {
			return nil
		}

		// Return early if the GroupVersionKind doesn't match what we expect.
		infraGVK := m.Spec.Template.Spec.InfrastructureRef.GroupVersionKind()
		if gvk != infraGVK {
			return nil
		}

		return []reconcile.Request{
			{
				NamespacedName: client.ObjectKey{
					Namespace: m.Namespace,
					Name:      m.Spec.Template.Spec.InfrastructureRef.Name,
				},
			},
		}
	}
}

// AzureClusterToAzureMachinePool is a handler.ToRequestsFunc to be used to enqeue
// requests for reconciliation of AzureMachinePools.
func (r *AzureMachinePoolReconciler) AzureClusterToAzureMachinePool(o handler.MapObject) []ctrl.Request {
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
	machinepoolList := &capiv1alpha2.MachinePoolList{}
	if err := r.List(context.TODO(), machinepoolList, client.InNamespace(c.Namespace), client.MatchingLabels(labels)); err != nil {
		log.Error(err, "failed to list Machines")
		return nil
	}
	for _, m := range machinepoolList.Items {
		if m.Spec.Template.Spec.InfrastructureRef.Name == "" {
			continue
		}
		name := client.ObjectKey{Namespace: m.Namespace, Name: m.Spec.Template.Spec.InfrastructureRef.Name}
		result = append(result, ctrl.Request{NamespacedName: name})
	}

	return result
}

func (r *AzureMachinePoolReconciler) Reconcile(req ctrl.Request) (_ ctrl.Result, reterr error) {
	_ = context.Background()
	log := r.Log.WithValues("azuremachinepool", req.NamespacedName)

	ctx := context.Background()
	machine, err := r.getMachinePoolContext(ctx, req)
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
	if machine.MachinePool.Spec.Template.Spec.Bootstrap.Data == nil {
		log.Info("Bootstrap data is not yet available")
		return ctrl.Result{}, nil
	}

	defer func() {
		if err := machine.Close(ctx); err != nil && reterr == nil {
			reterr = err
			log.Error(err, "Error closing machine context")
		}
	}()

	if err := r.reconcileMachinePool(ctx, machine); err != nil {
		log.Error(err, "Error reconciling machine")
		return ctrl.Result{}, nil
	}
	if err := r.reconcileMachinePoolInstances(ctx, machine); err != nil {
		log.Error(err, "Error reconciling machine instance")
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AzureMachinePoolReconciler) getMachinePoolContext(ctx context.Context, req ctrl.Request) (*machinePoolContext, error) {
	log := r.Log.WithValues("azuremachinepool", req.NamespacedName)
	instance := &v1alpha2.AzureMachinePool{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		return nil, err
	}

	machine, err := util.GetOwnerMachinePool(ctx, r.Client, instance.ObjectMeta)
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
	return &machinePoolContext{
		Client:           r.Client,
		AzureMachinePool: instance,
		AzureCluster:     azureCluster,
		MachinePool:      machine,
		Cluster:          cluster,
		patchHelper:      helper,
	}, nil
}

func (r *AzureMachinePoolReconciler) reconcileMachinePool(ctx context.Context, machinepool *machinePoolContext) error {
	log := r.Log.WithValues("azuremachinepool", fmt.Sprintf("%s/%s", machinepool.Namespace, machinepool.Name))

	scalesets := compute.NewVirtualMachineScaleSetsClient(machinepool.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&scalesets.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	scaleset, err := scalesets.Get(ctx, machinepool.Spec.ResourceGroup.Name, machinepool.Spec.Name)
	if err != nil && !notFound(err) {
		return fmt.Errorf("failed to get vm scale set [%w]", err)
	}

	applyMachinePoolSpec(machinepool, &scaleset)

	future, err := scalesets.CreateOrUpdate(ctx, machinepool.Spec.ResourceGroup.Name, machinepool.Spec.Name, scaleset)
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
	if scaleset.ID != nil {
		machinepool.Spec.ProviderID = to.StringPtr(fmt.Sprintf("azure://%s", *scaleset.ID))
		machinepool.Status.Ready = true
		log.Info("Setting ProviderID and Ready", "machinepool.Spec.ProviderID", *machinepool.Spec.ProviderID, "machinepool.Status.Ready", machinepool.Status.Ready)
	}
	return nil
}

func (r *AzureMachinePoolReconciler) reconcileMachinePoolInstances(ctx context.Context, machinepool *machinePoolContext) error {
	log := r.Log.WithValues("azuremachinepool", fmt.Sprintf("%s/%s", machinepool.Namespace, machinepool.Name))

	vms := compute.NewVirtualMachineScaleSetVMsClient(machinepool.Spec.ResourceGroup.SubscriptionID)
	err := authorizeFromFile(&vms.Client)
	if err != nil {
		return fmt.Errorf("failed to auth [%w]", err)
	}

	instances := 0
	itr, err := vms.ListComplete(ctx, machinepool.Spec.ResourceGroup.Name, machinepool.Spec.Name, "", "", "")
	for ; itr.NotDone(); err = itr.NextWithContext(ctx) {
		if err != nil {
			return fmt.Errorf("failed to iterate vm scale sets [%w]", err)
		}
		vm := itr.Value()
		instances++
		log.Info("Found instance", "ID", *vm.ID)
	}
	machinepool.Status.Replicas = int32(instances)
	log.Info("MachinePool Replica Count", "machinepool.Status.Replicas", machinepool.Status.Replicas)
	return nil
}

func applyMachinePoolSpec(mp *machinePoolContext, in *compute.VirtualMachineScaleSet) {
	vmss := newVMSS(in)
	vmss.SetName(mp.Spec.Name)
	vmss.SetRegion(&mp.Spec.ResourceGroup)
	vmss.SetSKU(mp.Spec.SKU)
	if mp.MachinePool.Spec.Replicas != nil {
		vmss.SetCapacity(int64(*mp.MachinePool.Spec.Replicas))
	}
	vmss.SetPrefix(mp.Spec.Name)
	vmss.SetCustomData(*mp.MachinePool.Spec.Template.Spec.Bootstrap.Data)
	vmss.SetSSHPublicKey(mp.Spec.SSHPublicKey)
	vmss.SetUserAssignedIdentity(&mp.Spec.ResourceGroup)
	vmss.SetOSDiskSize(128)
	vmss.SetSubnet(mp.SubnetID(mp.Spec.Subnet))
}
