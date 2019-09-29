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

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	infrastructurev1alpha2 "github.com/juan-lee/capz/api/v1alpha2"
)

// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azuremachinepools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=azuremachinepools/status,verbs=get;update;patch

// AzureMachinePoolReconciler reconciles a AzureMachinePool object
type AzureMachinePoolReconciler struct {
	client.Client
	Log logr.Logger
}

func (r *AzureMachinePoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infrastructurev1alpha2.AzureMachinePool{}).
		Complete(r)
}

func (r *AzureMachinePoolReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("azuremachinepool", req.NamespacedName)

	return ctrl.Result{}, nil
}
