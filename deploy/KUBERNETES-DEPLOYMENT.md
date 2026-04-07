# KubeSentinel Kubernetes Deployment Guide

This guide explains how to deploy KubeSentinel as a DaemonSet in your Kubernetes cluster.

## Prerequisites

- Kubernetes 1.20+
- `kubectl` configured to access your cluster
- Falco installed and running on your cluster nodes
- (Optional) Docker image for KubeSentinel available in your registry

## Quick Start

### 1. Create Secrets

First, create the secrets namespace and add your API keys:

```bash
# Create the namespace
kubectl create namespace kubesentinel

# Option A: Create from command line
kubectl create secret generic kubesentinel-secrets \
  --from-literal=gemini-api-key='YOUR_GEMINI_API_KEY' \
  --from-literal=training-api-token='YOUR_SECURE_TOKEN' \
  -n kubesentinel

# Option B: Edit the template and apply
# Edit deploy/kubesentinel-secrets-template.yaml with your values
kubectl apply -f deploy/kubesentinel-secrets-template.yaml
```

### 2. Deploy KubeSentinel

Deploy the DaemonSet with all RBAC resources:

```bash
kubectl apply -f deploy/kubesentinel-daemonset.yaml
```

### 3. Verify Deployment

```bash
# Check DaemonSet status
kubectl get daemonset -n kubesentinel
kubectl describe daemonset kubesentinel -n kubesentinel

# Check pod status
kubectl get pods -n kubesentinel
kubectl logs -n kubesentinel -l app=kubesentinel --tail=50 -f

# Check RBAC
kubectl get serviceaccount -n kubesentinel
kubectl get clusterrole kubesentinel
kubectl get clusterrolebinding kubesentinel
```

## What Gets Created

### RBAC Resources

- **ServiceAccount** (`kubesentinel`) - Identity for the DaemonSet
- **ClusterRole** (`kubesentinel`) - Permissions to:
  - Read Pods and logs across all namespaces
  - Read Events, Namespaces, Nodes
  - Read Deployments, StatefulSets, DaemonSets
  - Read NetworkPolicies
  - Read RBAC resources
  - Read PodSecurityPolicies

- **ClusterRoleBinding** (`kubesentinel`) - Binds ServiceAccount to ClusterRole

### Configuration

- **Namespace** (`kubesentinel`) - Dedicated namespace for KubeSentinel
- **ConfigMap** (`kubesentinel-config`) - KubeSentinel configuration
- **Secret** (`kubesentinel-secrets`) - Sensitive credentials

### Workload

- **DaemonSet** (`kubesentinel`) - Runs on every node (including control-plane)
- **Service** (`kubesentinel-ai`) - Exposes the AI module API (optional)

## Configuration

### Falco Socket Access

KubeSentinel requires access to the Falco socket at `/run/falco/falco.sock`. The DaemonSet mounts this from the host:

```yaml
volumeMounts:
  - name: falco-socket
    mountPath: /run/falco
    readOnly: true
```

If your Falco socket is in a different location, update the `hostPath` in the DaemonSet.

### Data Persistence

Forensics data is stored in an `emptyDir` volume (2Gi limit). For production:

1. Replace `emptyDir` with `PersistentVolumeClaim`:

```yaml
- name: data
  persistentVolumeClaim:
    claimName: kubesentinel-data-pvc
```

2. Create a PVC:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: kubesentinel-data-pvc
  namespace: kubesentinel
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Tolerations

The DaemonSet tolerates:
- Control-plane node taints (`node-role.kubernetes.io/control-plane`)
- Master node taints (`node-role.kubernetes.io/master`)
- Node NotReady and Unreachable conditions

To monitor only specific nodes, add `nodeSelector` or `affinity` rules.

### Resource Limits

Default requests/limits:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

Adjust based on your cluster size and forensics data volume.

## Environment Variables

Set in the Secret:

- `GEMINI_API_KEY` - Optional, for AI-powered analysis
- `TRAINING_API_TOKEN` - Required for securing the `/train` endpoint

## Security Considerations

1. **Run as root**: KubeSentinel requires root to access the Falco socket
2. **Read-only root**: Root filesystem is mounted as read-only
3. **No privilege escalation**: `allowPrivilegeEscalation` is false
4. **Limited capabilities**: Only `NET_RAW` capability is added (dropped all others)
5. **Secrets**: Keep API keys in Kubernetes Secrets, not in the image

## Troubleshooting

### DaemonSet pods not running

```bash
# Check pod events
kubectl describe pod -n kubesentinel <pod-name>

# Check logs
kubectl logs -n kubesentinel <pod-name>

# Check RBAC permissions
kubectl auth can-i get pods --as=system:serviceaccount:kubesentinel:kubesentinel
```

### Falco socket not found

```bash
# Verify Falco is running on nodes
kubectl get daemonset -n falco  # Adjust namespace as needed

# Check socket path on node
kubectl debug node/<node-name> -it --image=busybox
# Inside the container:
ls -la /run/falco/
```

### High memory usage

- Increase `limits.memory`
- Reduce forensics `retention_days`
- Configure `max_size_mb` appropriately

## Updating Configuration

Edit the ConfigMap and redeploy:

```bash
kubectl edit configmap kubesentinel-config -n kubesentinel
# KubeSentinel pods will need to restart to pick up changes
kubectl rollout restart daemonset/kubesentinel -n kubesentinel
```

## Production Deployment

For production, consider:

1. **Custom image**: Build a Docker image with the actual KubeSentinel binary
2. **Image registry**: Push to your private registry
3. **PersistentVolumes**: Replace `emptyDir` with proper PVC
4. **Resource quotas**: Set namespace-level resource quotas
5. **Network policies**: Restrict network access to KubeSentinel pods
6. **Monitoring**: Add Prometheus metrics endpoint
7. **Multi-cluster**: Deploy to multiple clusters with centralized reporting

## Related Commands

```bash
# View all KubeSentinel resources
kubectl get all -n kubesentinel

# View RBAC permissions
kubectl describe clusterrole kubesentinel

# Check resource usage
kubectl top daemonset kubesentinel -n kubesentinel

# Stream all logs from all pods
kubectl logs -n kubesentinel -f -l app=kubesentinel --all-containers

# Delete entire deployment
kubectl delete namespace kubesentinel
```

## Notes

- The DaemonSet image is currently a placeholder (`curlimages/curl`). Replace with actual KubeSentinel image.
- Falco must be installed separately (not included in this manifest)
- AI module can be deployed separately or integrated into the DaemonSet containers
