"""
Unit tests for CSPM manifest scanner
"""

import pytest
from cspm.manifest_scanner import ManifestScanner
import yaml


def test_detect_privileged_container():
    """Test detection of privileged containers."""
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'test'},
        'spec': {
            'containers': [{
                'name': 'app',
                'image': 'nginx',
                'securityContext': {'privileged': True}
            }]
        }
    }
    
    scanner = ManifestScanner()
    findings = scanner._check_pod_spec(manifest, 'test')
    
    assert len(findings) > 0
    assert any(f['rule'] == 'privileged_container' for f in findings)
    assert any(f['severity'] == 'CRITICAL' for f in findings)


def test_detect_missing_resource_limits():
    """Test detection of missing resource limits."""
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'test'},
        'spec': {
            'containers': [{
                'name': 'app',
                'image': 'nginx'
            }]
        }
    }
    
    scanner = ManifestScanner()
    findings = scanner._check_pod_spec(manifest, 'test')
    
    assert any(f['rule'] == 'missing_resource_limits' for f in findings)
    assert any(f['severity'] == 'HIGH' for f in findings)


def test_detect_runs_as_root():
    """Test detection of containers running as root."""
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'test'},
        'spec': {
            'containers': [{
                'name': 'app',
                'image': 'nginx',
                'securityContext': {}
            }]
        }
    }
    
    scanner = ManifestScanner()
    findings = scanner._check_pod_spec(manifest, 'test')
    
    assert any(f['rule'] == 'runs_as_root' for f in findings)


def test_no_findings_for_secure_pod():
    """Test that secure pods have minimal findings."""
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'secure'},
        'spec': {
            'containers': [{
                'name': 'app',
                'image': 'nginx:1.21',
                'securityContext': {
                    'privileged': False,
                    'runAsUser': 1000,
                    'runAsNonRoot': True,
                    'readOnlyRootFilesystem': True
                },
                'resources': {
                    'limits': {
                        'cpu': '100m',
                        'memory': '128Mi'
                    }
                }
            }]
        }
    }
    
    scanner = ManifestScanner()
    findings = scanner._check_pod_spec(manifest, 'secure')
    
    # Should not have critical/high issues
    critical_findings = [f for f in findings if f['severity'] == 'CRITICAL']
    assert len(critical_findings) == 0


def test_detect_overly_permissive_rbac():
    """Test detection of overly permissive RBAC rules."""
    manifest = {
        'apiVersion': 'rbac.authorization.k8s.io/v1',
        'kind': 'ClusterRole',
        'metadata': {'name': 'admin'},
        'rules': [{
            'apiGroups': ['*'],
            'verbs': ['*'],
            'resources': ['*']
        }]
    }
    
    scanner = ManifestScanner()
    findings = scanner._check_rbac(manifest, 'admin')
    
    assert len(findings) > 0
    assert any(f['rule'] == 'overly_permissive_rbac' for f in findings)


def test_detect_hostpath_mounts():
    """Test detection of hostPath volume mounts."""
    manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': 'test'},
        'spec': {
            'containers': [{
                'name': 'app',
                'image': 'nginx'
            }],
            'volumes': [{
                'name': 'host-vol',
                'hostPath': {
                    'path': '/etc/config'
                }
            }]
        }
    }
    
    scanner = ManifestScanner()
    findings = scanner._check_pod_spec(manifest, 'test')
    
    assert any(f['rule'] == 'hostpath_mount' for f in findings)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
