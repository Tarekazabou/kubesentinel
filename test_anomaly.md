# Filtered monitoring command 
kubectl logs -f -n falco -l app.kubernetes.io/name=falco --all-containers | \
./bin/kubesentinel monitor-stdin \
  --namespace kubesentinel-test \
  --pod insecure-test-pod \
  --ai-endpoint=http://localhost:5000

# 1. Read sensitive file (triggers "Sensitive file opened for reading" or "Read sensitive file")
kubectl exec -it insecure-test-pod -n kubesentinel-test -- cat /etc/shadow

# 2. Write below /etc (your fake-event rule)
kubectl exec -it insecure-test-pod -n kubesentinel-test -- sh -c "echo 'evil' > /etc/hosts.bak"

# 3. Spawn shell in container (classic "Terminal shell in container")
kubectl exec -it insecure-test-pod -n kubesentinel-test -- /bin/bash

# 4. Suspicious network tool (netcat listener or scan)
kubectl exec -it insecure-test-pod -n kubesentinel-test -- sh -c "nc -l -p 4444 & sleep 2; kill %1"

# 5. Install package / apt-get (triggers "Package management process launched")
kubectl exec -it insecure-test-pod -n kubesentinel-test -- apt-get update

# 6. Privileged operations (mount, modprobe, etc.)
kubectl exec -it insecure-test-pod -n kubesentinel-test -- sh -c "mount /host/proc /tmp/proc"

# 7. Run as root + suspicious binary
kubectl exec -it insecure-test-pod -n kubesentinel-test -- sh -c "whoami && ls -la /root"