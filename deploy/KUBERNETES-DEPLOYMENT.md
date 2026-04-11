# KubeSentinel Kubernetes Deployment Guide

This guide explains how to deploy KubeSentinel as a DaemonSet in your Kubernetes cluster.

## Prerequisites

- Kubernetes 1.20+
- `kubectl` configured to access your cluster
- **Falco installed and running on your cluster nodes** (see [Falco Installation](#falco-installation) section)
- Docker image for KubeSentinel pushed to your registry
- (Optional) Docker image for kubesentinel-ai pushed to your registry

## Falco Installation

**KubeSentinel depends on Falco to provide runtime security events.** If Falco is not installed, the monitor will exit immediately with no events to process.

### Falco Socket Path

All components in KubeSentinel are configured to use the standard Falco socket path:

```
/run/falco/falco.sock
```

**Important**: Do not change this path. Falco writes to `/run/falco` on standard Linux installations (not `/var/run/falco`). Both the DaemonSet and Docker Compose use this path. If you customize your Falco installation to use a different socket path, you must update:

- `config/config.yaml`: `runtime.falco.socket_path` setting
- `docker-compose.yml`: Volume mount for `/run/falco`
- `deploy/kubesentinel-daemonset.yaml`: Volume mount in the DaemonSet spec

### Option 1: Install Falco via Helm (Recommended)

```bash
# Add Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with KubeSentinel-optimized configuration
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  -f deploy/falco-values.yaml

# Verify Falco is running
kubectl get pods -n falco
kubectl logs -n falco -l app=falco --tail=20 -f
```

### Option 2: Manual Installation

If you prefer not to use Helm, refer to the [Falco documentation](https://falco.org/docs/getting-started/installation/).

### Verify Falco Socket

```bash
# SSH into a worker node and check for the Falco socket
sudo ls -la /run/falco/

# Output should show:
# -rw-r--r-- 1 root root 0 Apr 10 10:00 falco.sock
```

## AI Service Health Checks

The kubesentinel-ai Deployment includes a HEALTHCHECK that verifies the Flask service is responding:

- **Interval**: 30 seconds
- **Timeout**: 10 seconds (reasonable for a simple HTTP `/health` GET request)
- **Start Period**: 5 seconds (grace period on startup)
- **Retries**: 3 (marks unhealthy after 3 consecutive timeouts)

This configuration ensures that if the AI service becomes unresponsive, Kubernetes will restart the pod within ~1 minute, preventing long hangs during development or demos.

## Storage Configuration

KubeSentinel stores forensic evidence and reports in `/data`, which must persist across pod restarts. The deployment includes:

- **PersistentVolume (PV)**: Configured with hostPath at `/mnt/data/kubesentinel` for Minikube/single-node clusters
- **PersistentVolumeClaim (PVC)**: Claims 5Gi storage for forensics and reports

### For Minikube

Data is stored on the Minikube host at `/mnt/data/kubesentinel`. This survives pod restarts but is lost if Minikube is deleted.

```bash
# Access persisted data from host
minikube ssh
ls -la /mnt/data/kubesentinel/forensics
ls -la /mnt/data/kubesentinel/reports
```

### For Production Clusters

Before deploying, edit the PersistentVolume in `kubesentinel-daemonset.yaml` to use your cluster's storage backend:

**Option 1: NFS Storage**
```yaml
spec:
  nfs:
    server: 192.168.1.100
    path: "/exports/kubesentinel"
```

**Option 2: Local Storage**
```yaml
spec:
  local:
    path: /mnt/kubesentinel
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - node-1
```

**Option 3: Cloud Storage (EBS, GCP Persistent Disk, etc.)**
Replace the PV with a StorageClass and let Kubernetes provision it.

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
- **Service** (`kubesentinel-metrics`) - Exposes Prometheus metrics on port 8080
- **PersistentVolume** (`kubesentinel-data-pv`) - Stores forensics and reports
- **PersistentVolumeClaim** (`kubesentinel-data-pvc`) - Claims persistent storage (5Gi)

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

### Prometheus Metrics

KubeSentinel exposes Prometheus metrics on port `8080/metrics` by default. A dedicated Service (`kubesentinel-metrics`) exposes these metrics for scraping.

#### Access metrics locally

```bash
# Port-forward to the metrics service
kubectl port-forward -n kubesentinel svc/kubesentinel-metrics 8080:8080

# in another terminal
curl http://localhost:8080/metrics

# View specific metrics
curl -s http://localhost:8080/metrics | grep kubesentinel_
```

#### Configure Prometheus to scrape KubeSentinel

Add this job to your Prometheus config:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'kubesentinel'
    kubernetes_sd_configs:
      - role: service
        namespaces:
          names:
            - kubesentinel
    relabel_configs:
      # Only scrape services with the scrape annotation
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_service_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __param_target
```

#### Available metrics

```
kubesentinel_falco_events_total{severity="..."}       # Falco events processed
kubesentinel_anomalies_detected_total{...}            # Anomalies found
kubesentinel_violations_found_total{severity="..."}   # Policy violations
kubesentinel_report_generation_time_seconds           # Report generation time
kubesentinel_ai_service_latency_seconds               # AI service latency
```

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
3. **Storage backend**: The PV currently uses `hostPath`. Replace with NFS, EBS, or your cloud provider's storage class
4. **Resource quotas**: Set namespace-level resource quotas
5. **Network policies**: Restrict network access to KubeSentinel pods
6. **Monitoring**: Add Prometheus metrics endpoint
7. **Multi-cluster**: Deploy to multiple clusters with centralized reporting

## Cleanup and Uninstall

### Preserve data during uninstall

The PersistentVolume retains data with `persistentVolumeReclaimPolicy: Retain`. Data survives namespace deletion:

```bash
# Delete the entire KubeSentinel deployment (but keep data)
kubectl delete namespace kubesentinel

# Data is still preserved at /mnt/data/kubesentinel (Minikube) or your storage backend
# To re-deploy, simply re-apply the manifest

# View PV and PVC status
kubectl get pv
kubectl get pvc -n kubesentinel  # Will show "Terminating" or "Pending" after delete
```

### Complete removal including data

To fully remove everything including persisted data:

```bash
# Delete Falco (optional)
helm delete falco -n falco
kubectl delete namespace falco

# Delete KubeSentinel
kubectl delete namespace kubesentinel

# Delete the PersistentVolume (if using hostPath on Minikube)
kubectl delete pv kubesentinel-data-pv

# Clean up data directory (Minikube)
minikube ssh 'sudo rm -rf /mnt/data/kubesentinel'

# Delete the namespace
kubectl delete namespace kubesentinel
```

## Related Commands

### View resources and status

```bash
# View all KubeSentinel resources
kubectl get all -n kubesentinel

# View storage resources
kubectl get pv,pvc -n kubesentinel

# View RBAC permissions
kubectl describe clusterrole kubesentinel

# View ConfigMap
kubectl get configmap -n kubesentinel
kubectl describe cm kubesentinel-config -n kubesentinel

# Check resource usage
kubectl top daemonset kubesentinel -n kubesentinel

# Stream all logs from all pods
kubectl logs -n kubesentinel -f -l app=kubesentinel --all-containers
```

### Access collected data

```bash
# Copy forensics from pod
kubectl cp kubesentinel/<pod-name>:/data/forensics ./forensics-backup -n kubesentinel

# Copy reports from pod
kubectl cp kubesentinel/<pod-name>:/data/reports ./reports-backup -n kubesentinel

# View live forensics (Minikube)
minikube ssh
ls -lah /mnt/data/kubesentinel/forensics/
tail -f /mnt/data/kubesentinel/forensics/*.json
```

- The DaemonSet image is currently a placeholder (`curlimages/curl`). Replace with actual KubeSentinel image.
- Falco must be installed separately (not included in this manifest)
- AI module can be deployed separately or integrated into the DaemonSet containers
