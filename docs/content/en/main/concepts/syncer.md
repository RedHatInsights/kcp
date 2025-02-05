---
title: "Registering Kubernetes Clusters using syncer"
linkTitle: "Syncer"
weight: 1
description: >
  How to register Kubernetes clusters using syncer
---

In order to register a Kubernetes clusters with the kcp server,
users have to install a special component named [syncer](https://github.com/kcp-dev/kcp/tree/main/docs/architecture#syncer).

## Requirements

- kcp server
- [kcp kubectl plugin](./kubectl-kcp-plugin.md)
- kubernetes cluster

## Instructions

1. (Optional) Skip this step, if you already have a physical cluster.
   Create a kind cluster to back the sync target:

    ```sh
    $ kind create cluster
    Creating cluster "kind" ...
    <snip>
    Set kubectl context to "kind-kind"
    You can now use your cluster with:

    kubectl cluster-info --context kind-kind
    ```

{{% alert title="Note" color="primary" %}}
This step sets current context to the new kind cluster. Make sure to use a KCP kubeconfig for the next steps unless told otherwise.
{{% /alert %}}

1. Create an organisation and immediately enter it:

    ```sh
    $ kubectl kcp workspace create my-org --enter
    Workspace "my-org" (type root:organization) created. Waiting for it to be ready...
    Workspace "my-org" (type root:organization) is ready to use.
    Current workspace is "root:my-org" (type "root:organization").
    ```

1. Enable the syncer for a p-cluster:

    ```sh
    kubectl kcp workload sync <mycluster> --syncer-image <image name> -o syncer.yaml
    ```

    Where `<image name>` [one of the syncer images](https://github.com/kcp-dev/kcp/pkgs/container/kcp%2Fsyncer) for your corresponding KCP release (e.g. `ghcr.io/kcp-dev/kcp/syncer:v0.7.5`).

1. Apply the manifest to the p-cluster:

    ```sh
    $ KUBECONFIG=<pcluster-config> kubectl apply -f syncer.yaml
    namespace/kcp-syncer-kind-1owee1ci created
    serviceaccount/kcp-syncer-kind-1owee1ci created
    secret/kcp-syncer-kind-1owee1ci-token created
    clusterrole.rbac.authorization.k8s.io/kcp-syncer-kind-1owee1ci created
    clusterrolebinding.rbac.authorization.k8s.io/kcp-syncer-kind-1owee1ci created
    secret/kcp-syncer-kind-1owee1ci created
    deployment.apps/kcp-syncer-kind-1owee1ci created
    ```

    and it will create a `kcp-syncer` deployment:

    ```sh
    $ KUBECONFIG=<pcluster-config> kubectl -n kcp-syncer-kind-1owee1ci get deployments
    NAME     READY   UP-TO-DATE   AVAILABLE   AGE
    kcp-syncer   1/1     1            1           13m
    ```

1. Wait for the kcp sync target to go ready:

    ```bash
    kubectl wait --for=condition=Ready synctarget/<mycluster>
    ```
### Select resources to sync.

Syncer will by default use the `kubernetes` APIExport in `root:compute` workspace and sync `deployments/services/ingresses`
to the physical cluster. The related API schemas of the physical cluster should be comptible with kubernetes 1.24. User can
select to sync other resources in physical clusters or from other APIExports on kcp server.

To sync resources that the KCP server does not have an APIExport to support yet, run

```sh
kubectl kcp workload sync <mycluster> --syncer-image <image name> --resources foo.bar -o syncer.yaml
```

And apply the generated manifests to the physical cluster. The syncer will then import the API schema of foo.bar
to the workspace of the synctarget, following up with an auto generated kubernetes APIExport/APIBinding in the same workspace.
You can then create foo.bar in this workspace, or create an APIBinding in another workspace to bind this APIExport.

To sync resource from another existing APIExport in the KCP server, run

```sh
kubectl kcp workload sync <mycluster> --syncer-image <image name> --apiexports another-workspace|another-apiexport -o syncer.yaml
```

Syncer will start syncing the resources in this APIExport as long as the physical clusters has the compatible API schemas.

To see if a certain resource is supported to be synced by the syncer, you can check the state of the `syncedResources` in `SyncTarget`
status.

### Running a workload

1. Create a deployment:

    ```sh
    kubectl create deployment kuard --image gcr.io/kuar-demo/kuard-amd64:blue
    ```

{{% alert title="Note" color="primary" %}}
Replace "gcr.io/kuar-demo/kuard-amd64:blue" with "gcr.io/kuar-demo/kuard-arm64:blue" in case you're running
an Apple M1 based virtual machine.
{{% /alert %}}

1. Verify the deployment on the local workspace:

    ```sh
    $ kubectl rollout status deployment/kuard
    Waiting for deployment "kuard" rollout to finish: 0 of 1 updated replicas are available...
    deployment "kuard" successfully rolled out
    ```

## For syncer development

### Running in a kind cluster with a local registry

You can run the syncer in a kind cluster for development.

1. Create a `kind` cluster with a local registry to simplify syncer development
   by executing the following script:

   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/kubernetes-sigs/kind/main/site/static/examples/kind-with-registry.sh)"
   ```

1. Install `ko`:

    ```sh
    go install github.com/google/ko@latest
    ```

1. Build image and push to the local registry integrated with `kind`:

    ```sh
    KO_DOCKER_REPO=localhost:5001 ko publish ./cmd/syncer -t <image tag>
    ```

    By default `ko` will build for `amd64`. To build for `arm64`
    (e.g. apple silicon), specify `--platform=linux/arm64`.

1. Create an organisation and immediately enter it:

    ```sh
    $ kubectl kcp workspace create my-org --enter
    Workspace "my-org" (type root:organization) created. Waiting for it to be ready...
    Workspace "my-org" (type root:organization) is ready to use.
    Current workspace is "root:my-org" (type "root:organization").
    ```

1. To use the image pushed to the local registry, supply `<image name>` to the
   `kcp workload sync` plugin command, where `<image name>` is
   from the output of `ko publish`:

    ```sh
    kubectl kcp workload sync <mycluster> --syncer-image <image name> -o syncer.yaml
    ```

1. Apply the manifest to the p-cluster:

    ```sh
    $ KUBECONFIG=<pcluster-config> kubectl apply -f syncer.yaml
    namespace/kcp-syncer-kind-1owee1ci created
    serviceaccount/kcp-syncer-kind-1owee1ci created
    secret/kcp-syncer-kind-1owee1ci-token created
    clusterrole.rbac.authorization.k8s.io/kcp-syncer-kind-1owee1ci created
    clusterrolebinding.rbac.authorization.k8s.io/kcp-syncer-kind-1owee1ci created
    secret/kcp-syncer-kind-1owee1ci created
    deployment.apps/kcp-syncer-kind-1owee1ci created
    ```

    and it will create a `kcp-syncer` deployment:

    ```sh
    $ KUBECONFIG=<pcluster-config> kubectl -n kcp-syncer-kind-1owee1ci get deployments
    NAME     READY   UP-TO-DATE   AVAILABLE   AGE
    kcp-syncer   1/1     1            1           13m
    ```

1. Wait for the kcp sync target to go ready:

    ```bash
    kubectl wait --for=condition=Ready synctarget/<mycluster>
    ```

### Running locally

TODO(m1kola): we need a less hacky way to run locally: needs to be more close
to what we have when running inside the kind with own kubeconfig.

This assumes that KCP is also being run locally.

1. Create a kind cluster to back the sync target:

    ```sh
    $ kind create cluster
    Creating cluster "kind" ...
    <snip>
    Set kubectl context to "kind-kind"
    You can now use your cluster with:

    kubectl cluster-info --context kind-kind
    ```

1. Make sure to use kubeconfig for your local KCP:

    ```bash
    export KUBECONFIG=.kcp/admin.kubeconfig
    ```

1. Create an organisation and immediately enter it:

    ```sh
    $ kubectl kcp workspace create my-org --enter
    Workspace "my-org" (type root:organization) created. Waiting for it to be ready...
    Workspace "my-org" (type root:organization) is ready to use.
    Current workspace is "root:my-org" (type "root:organization").
    ```

1. Enable the syncer for a p-cluster:

    ```sh
    kubectl kcp workload sync <mycluster> --syncer-image <image name> -o syncer.yaml
    ```

    `<image name>` can be anything here as it will only be used to generate `syncer.yaml` which we are not going to apply.

1. Gather data required for the syncer:

    ```bash
    syncTargetName=<mycluster>
    syncTargetUID=$(kubectl get synctarget $syncTargetName -o jsonpath="{.metadata.uid}")
    fromCluster=$(kubectl ws current --short)
    ```

1. Run the following snippet:

    ```bash
    go run ./cmd/syncer \
      --from-kubeconfig=.kcp/admin.kubeconfig \
      --from-context=base \
      --to-kubeconfig=$HOME/.kube/config \
      --sync-target-name=$syncTargetName \
      --sync-target-uid=$syncTargetUID \
      --from-cluster=$fromCluster \
      --resources=configmaps \
      --resources=deployments.apps \
      --resources=secrets \
      --resources=serviceaccounts \
      --qps=30 \
      --burst=20
    ```

1. Wait for the kcp sync target to go ready:

    ```bash
    kubectl wait --for=condition=Ready synctarget/<mycluster>
    ```
