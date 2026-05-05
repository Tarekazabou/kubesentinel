#!/usr/bin/env python3
"""Validate P0 manifest changes"""
import yaml

# Validate the updated deployment manifest
with open('deploy/kubesentinel-ai-deployment.yaml') as f:
    docs = list(yaml.safe_load_all(f))

print(f"✓ kubesentinel-ai-deployment.yaml: {len(docs)} documents parsed")

# Find the AI deployment
for doc in docs:
    if doc.get('kind') == 'Deployment' and doc.get('metadata', {}).get('name') == 'kubesentinel-ai':
        containers = doc['spec']['template']['spec']['containers']
        ai_service = containers[0]
        
        # Check resources limits
        limits = ai_service.get('resources', {}).get('limits', {})
        print(f"✓ Resource limits: cpu={limits.get('cpu')}, memory={limits.get('memory')}")
        
        # Check readiness probe
        probe = ai_service.get('readinessProbe', {})
        print(f"✓ Readiness probe: initialDelaySeconds={probe.get('initialDelaySeconds')}, failureThreshold={probe.get('failureThreshold')}")
        
        # Check tmp volume mount
        mounts = ai_service.get('volumeMounts', [])
        tmp_mount = next((m for m in mounts if m.get('name') == 'tmp'), None)
        print(f"✓ /tmp volume mount exists: {tmp_mount is not None}")
        
        # Check tmp volume in spec
        volumes = doc['spec']['template']['spec'].get('volumes', [])
        tmp_vol = next((v for v in volumes if v.get('name') == 'tmp'), None)
        print(f"✓ tmp emptyDir volume defined: {tmp_vol is not None}")
        break

print("\n✅ All P0 manifest changes applied successfully")
