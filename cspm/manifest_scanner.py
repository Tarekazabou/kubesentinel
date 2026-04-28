"""
Manifest Scanner - Scans Kubernetes YAML manifests for security misconfigurations
"""

import yaml
import json
from pathlib import Path
from typing import List, Dict

from cspm.manifest_contract import build_finding


class ManifestScanner:
    """Scanner for Kubernetes manifests to detect security issues."""
    
    def __init__(self):
        self.findings = []
    
    def scan_manifest(self, manifest_path: str) -> List[Dict]:
        """Scan a single K8s manifest file."""
        with open(manifest_path, 'r') as f:
            content = f.read()
        
        docs = yaml.safe_load_all(content)
        
        findings = []
        for doc in docs:
            if doc is None:
                continue
            findings.extend(self._check_resource(doc))
        
        return findings
    
    def _check_resource(self, resource: Dict) -> List[Dict]:
        """Check a single K8s resource for security issues."""
        findings = []
        kind = resource.get('kind', 'Unknown')
        name = resource.get('metadata', {}).get('name', 'Unknown')
        
        if kind in ['Pod', 'Deployment', 'DaemonSet', 'StatefulSet']:
            findings.extend(self._check_pod_spec(resource, name))
        
        if kind in ['Role', 'ClusterRole']:
            findings.extend(self._check_rbac(resource, name))
        
        if kind == 'NetworkPolicy':
            pass  # Check for network policies
        
        return findings
    
    def _check_pod_spec(self, resource: Dict, name: str) -> List[Dict]:
        """Check pod specs for security issues."""
        findings = []
        
        # Navigate to containers
        spec = resource.get('spec', {})
        if 'template' in spec:  # Deployment/DaemonSet/StatefulSet
            spec = spec['template'].get('spec', {})
        
        containers = spec.get('containers', [])
        
        for i, container in enumerate(containers):
            container_name = container.get('name', f'container-{i}')
            
            # Check 1: Privileged containers
            if container.get('securityContext', {}).get('privileged'):
                findings.append(build_finding(
                    rule_id='privileged_container',
                    severity='critical',
                    description=f'Container {container_name} in {name} is running as privileged',
                    remediation='Set securityContext.privileged to false'
                ))
            
            # Check 2: Missing resource limits
            if 'resources' not in container or not container['resources'].get('limits'):
                findings.append(build_finding(
                    rule_id='missing_resource_limits',
                    severity='high',
                    description=f'Container {container_name} in {name} has no resource limits',
                    remediation='Set resources.limits.cpu and resources.limits.memory'
                ))
            
            # Check 3: Running as root
            security_ctx = container.get('securityContext', {})
            if security_ctx.get('runAsUser') is None or security_ctx.get('runAsUser') == 0:
                findings.append(build_finding(
                    rule_id='runs_as_root',
                    severity='high',
                    description=f'Container {container_name} may run as root (runAsUser not set)',
                    remediation='Set securityContext.runAsUser to a non-zero value'
                ))
            
            # Check 4: hostPath mounts
            volumes = spec.get('volumes', [])
            for volume in volumes:
                if 'hostPath' in volume:
                    findings.append(build_finding(
                        rule_id='hostpath_mount',
                        severity='high',
                        description=f'Pod {name} mounts hostPath volume {volume["name"]}',
                        remediation='Use PersistentVolumes instead of hostPath'
                    ))
            
            # Check 5: Writable filesystem
            if not security_ctx.get('readOnlyRootFilesystem'):
                findings.append(build_finding(
                    rule_id='writable_filesystem',
                    severity='medium',
                    description=f'Container {container_name} has writable root filesystem',
                    remediation='Set securityContext.readOnlyRootFilesystem to true'
                ))
            
            # Check 6: Dangerous capabilities
            capabilities = security_ctx.get('capabilities', {})
            added_caps = capabilities.get('add', [])
            dangerous_caps = ['NET_ADMIN', 'SYS_ADMIN', 'SYS_MODULE']
            for cap in added_caps:
                if cap in dangerous_caps:
                    findings.append(build_finding(
                        rule_id='dangerous_capabilities',
                        severity='high',
                        description=f'Container {container_name} has dangerous capability: {cap}',
                        remediation=f'Remove {cap} from securityContext.capabilities.add'
                    ))
            
            # Check 7: Image pull policy
            image_pull_policy = container.get('imagePullPolicy', 'IfNotPresent')
            if image_pull_policy == 'Never':
                findings.append(build_finding(
                    rule_id='image_pull_never',
                    severity='medium',
                    description=f'Container {container_name} has imagePullPolicy set to Never',
                    remediation='Use Always or IfNotPresent for imagePullPolicy'
                ))
        
        return findings
    
    def _check_rbac(self, resource: Dict, name: str) -> List[Dict]:
        """Check RBAC resources for excessive permissions."""
        findings = []
        rules = resource.get('rules', [])
        
        for rule in rules:
            verbs = rule.get('verbs', [])
            resources = rule.get('resources', [])
            api_groups = rule.get('apiGroups', [''])
            
            # Check for wildcard permissions
            if '*' in verbs or '*' in resources or '*' in api_groups:
                findings.append(build_finding(
                    rule_id='overly_permissive_rbac',
                    severity='high',
                    description=f'Role {name} has wildcard permissions in verbs, resources, or apiGroups',
                    remediation='Restrict to specific verbs and resources'
                ))
            
            # Check for dangerous verbs
            dangerous_verbs = ['*', 'create', 'delete', 'deletecollection']
            if any(v in verbs for v in dangerous_verbs):
                if '*' in resources:
                    findings.append(build_finding(
                        rule_id='dangerous_permissions',
                        severity='critical',
                        description=f'Role {name} allows dangerous verbs on all resources',
                        remediation='Limit dangerous verbs to essential resources only'
                    ))
        
        return findings


def scan_directory(directory: str) -> List[Dict]:
    """Scan all YAML files in a directory."""
    scanner = ManifestScanner()
    all_findings = []
    
    for yaml_file in Path(directory).rglob('*.yaml'):
        try:
            findings = scanner.scan_manifest(str(yaml_file))
            for finding in findings:
                finding['path'] = str(yaml_file)
                finding['file'] = str(yaml_file)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Warning: Could not scan {yaml_file}: {e}")
    
    return all_findings


def scan_file(file_path: str) -> List[Dict]:
    """Scan a single manifest file."""
    scanner = ManifestScanner()
    findings = scanner.scan_manifest(file_path)
    for finding in findings:
        finding['path'] = file_path
        finding['file'] = file_path
    return findings
