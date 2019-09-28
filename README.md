# capz
Quick and dirty provider for testing out new features for cluster-api-provider-azure. This repo goes
away once cluster-api-provider-azure is updated to v1alpha2 and azure features such as standard load
balancer, managed identity, and vmss are integrated.

## Quickstart

``` bash
# Create a kind cluster to serve as a management cluster
kind create cluster --name=clusterapi
export KUBECONFIG="$(kind get kubeconfig-path --name="clusterapi")"

# Create identity required for provisioning
export AZURE_TENANT_ID=<provide tenant id>
export AZURE_SUBSCRIPTION_ID=<provided subscription id>
export AZURE_AUTH_LOCATION=$HOME/.azure/creds.json
mkdir -p ${AZURE_AUTH_LOCATION}

az ad sp create-for-rbac --sdk-auth \
    --role "User Access Administrator" \
    --scope "/subscriptions/${AZURE_SUBSCRIPTION_ID}" > ${AZURE_AUTH_LOCATION}

az role assignment create \
    --role contributor \
    --scope "/subscriptions/${AZURE_SUBSCRIPTION_ID}" \
    --assignee $(cat ${AZURE_AUTH_LOCATION} | jq -r .clientId)

# Build and Deploy cluster-api and provider to the kind cluster
export IMG=<provide repository info>/capz-controller:latest
export SSH_PUBLIC_KEY=$(cat $HOME/.ssh/<provide public key>)
export AZURE_B64ENCODED_CREDENTIALS=$(cat $HOME/.azure/creds.json | base64 -w0)
make docker-build docker-push install deploy

# Deploy Cluster
cat config/samples/infrastructure_v1alpha2_azurecluster.yaml | envsubst | kubectl apply -f -

# Deploy Control Plane Machine
cat config/samples/infrastructure_v1alpha2_azuremachine.yaml | envsubst | kubectl apply -f -

# Wait for Provisioning to complete
kubectl get cluster,machine -w

# Observe the new cluster
kubectl --kubeconfig <(k get secrets -n default capi-quickstart-kubeconfig -o json | jq -r '.data.value' | base64 -d) cluster-info
```
