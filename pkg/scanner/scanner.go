package scanner

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"kubesentinel/pkg/rules"
	"kubesentinel/pkg/types"
	"encoding/json"
)

// Scanner handles static analysis of Kubernetes manifests
type Scanner struct {
	RulesEngine *rules.RulesEngine
	Config      *ScanConfig
}

// ScanConfig holds scanner configuration
type ScanConfig struct {
	RulesPath         string
	SeverityThreshold string
	OutputFormat      string
}

// ScanResult represents the result of a manifest scan
type ScanResult struct {
	FilePath   string              `json:"file_path"`
	Violations []types.Violation   `json:"violations"`
	Metadata   map[string]string   `json:"metadata"`
	Passed     bool                `json:"passed"`
}

// Violation represents a security violation found during scanning

// K8sResource represents a parsed Kubernetes resource
type K8sResource struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   map[string]interface{} `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
}

// NewScanner creates a new static scanner instance
func NewScanner(config *ScanConfig) (*Scanner, error) {
	engine, err := rules.NewRulesEngine(config.RulesPath)
    if err != nil {
        return nil, err
    }
    return &Scanner{RulesEngine: engine, Config: config}, nil
}
// ScanPath scans all YAML files in the given path
func (s *Scanner) ScanPath(path string) ([]ScanResult, error) {
	files, err := s.discoverManifests(path)
	if err != nil {
		return nil, fmt.Errorf("failed to discover manifests: %w", err)
	}

	results := make([]ScanResult, 0, len(files))
	for _, file := range files {
		result, err := s.ScanFile(file)
		if err != nil {
			// Log error but continue scanning other files
			fmt.Printf("Warning: failed to scan %s: %v\n", file, err)
			continue
		}
		results = append(results, result)
	}
	if s.Config.OutputFormat == "json" {
        jsonData, err := json.MarshalIndent(results, "", "  ")
        if err != nil {
            return nil, err
        }
        fmt.Println(string(jsonData))
    }

	return results, nil
}

// ScanFile scans a single manifest file
func (s *Scanner) ScanFile(filePath string) (ScanResult, error) {
	result := ScanResult{
		FilePath:   filePath,
		Violations: []types.Violation{},
		Metadata:   make(map[string]string),
		Passed:     true,
	}

	// 1. Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return result, fmt.Errorf("failed to read manifest %s: %w", filePath, err)
	}

	// 2. Parse YAML (supports multi-document files)
	resources, err := s.parseYAML(content)
	if err != nil {
		return result, fmt.Errorf("failed to parse YAML in %s: %w", filePath, err)
	}

	if len(resources) == 0 {
		// Empty file or only comments — treat as passed but log warning
		return result, nil
	}

	// 3. Set basic metadata from first resource (can be improved later)
	firstResource := resources[0]
	result.Metadata["kind"] = firstResource.Kind
	if name, ok := firstResource.Metadata["name"].(string); ok && name != "" {
		result.Metadata["name"] = name
	}
	if ns, ok := firstResource.Metadata["namespace"].(string); ok && ns != "" {
		result.Metadata["namespace"] = ns
	}

	// 4. Scan each resource and collect violations
	for i, resource := range resources {
		violations := s.scanResource(resource)

		// Filter violations by configured severity threshold
		for _, v := range violations {
			if s.isSeverityAboveThreshold(v.Severity) {
				// Optional: enrich violation with more context
				v.Resource = fmt.Sprintf("%s/%s", resource.Kind, resource.Metadata["name"])
				if i > 0 {
					v.Path = fmt.Sprintf("--- document %d --- %s", i+1, v.Path)
				}
				result.Violations = append(result.Violations, v)
			}
		}
	}

	// 5. Determine pass/fail
	result.Passed = len(result.Violations) == 0

	return result, nil
}

// Helper: check if severity meets or exceeds configured threshold
func (s *Scanner) isSeverityAboveThreshold(sev string) bool {
	levels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	configLevel, exists := levels[strings.ToLower(s.Config.SeverityThreshold)]
	if !exists {
		configLevel = 2 // default to medium
	}

	sevLevel, exists := levels[strings.ToLower(sev)]
	if !exists {
		return false // unknown severity → skip
	}

	return sevLevel >= configLevel
}

// scanResource applies all rules to a single resource
func (s *Scanner) scanResource(resource K8sResource) []types.Violation {
	violations := []types.Violation{}

	// Check for privileged containers
	if v := s.checkPrivilegedContainers(resource); v != nil {
		violations = append(violations, *v)
	}

	// Check for missing resource limits
	if v := s.checkResourceLimits(resource); v != nil {
		violations = append(violations, *v)
	}

	// Check for root user
	if v := s.checkNonRootUser(resource); v != nil {
		violations = append(violations, *v)
	}

	// Check for read-only root filesystem
	if v := s.checkReadOnlyRootFS(resource); v != nil {
		violations = append(violations, *v)
	}

	// Check for security context
	if v := s.checkSecurityContext(resource); v != nil {
		violations = append(violations, *v)
	}

	// Apply custom rules from RulesEngine
	resourceMap := map[string]interface{}{
    "apiVersion": resource.APIVersion,
    "kind":       resource.Kind,
    "metadata":   resource.Metadata,
    "spec":       resource.Spec,
    // If your K8sResource has other top-level fields like "status", add them too
}

// Call the rules engine
    engineViolations := s.RulesEngine.Apply(resourceMap)

// Append them (use a consistent name)
    violations = append(violations, engineViolations...)

	return violations
}

// checkPrivilegedContainers checks for privileged container configurations
func (s *Scanner) checkPrivilegedContainers(resource K8sResource) *types.Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	// Navigate to containers spec
	containers := s.getContainers(resource)
	for _, container := range containers {
		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if privileged, ok := securityContext["privileged"].(bool); ok && privileged {
				return &types.Violation{
					RuleID:      "KS-PRIV-001",
					Severity:    "critical",
					Description: fmt.Sprintf("Privileged container found: %s", container["name"]),  // ← changed
					Resource:    s.getResourceName(resource),
					Remediation: "Set securityContext.privileged to false",
				}
			}
		}
	}

	return nil
}

// checkResourceLimits checks for missing CPU/memory limits
func (s *Scanner) checkResourceLimits(resource K8sResource) *types.Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		resources, ok := container["resources"].(map[string]interface{})
		if !ok {
			return &types.Violation{
				RuleID:      "SEC-002",
				Severity:    "high",
				Description:     "Container missing resource limits",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Add resources.limits.cpu and resources.limits.memory to container spec",
			}
		}

		limits, ok := resources["limits"].(map[string]interface{})
		if !ok || limits["cpu"] == nil || limits["memory"] == nil {
			return &types.Violation{
				RuleID:      "SEC-002",
				Severity:    "high",
				Description:     "Container missing CPU or memory limits",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Define both CPU and memory limits in resources.limits",
			}
		}
	}

	return nil
}

// checkNonRootUser checks if containers run as non-root
func (s *Scanner) checkNonRootUser(resource K8sResource) *types.Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if runAsNonRoot, ok := securityContext["runAsNonRoot"].(bool); !ok || !runAsNonRoot {
				return &types.Violation{
					RuleID:      "SEC-003",
					Severity:    "medium",
					Description:     "Container may run as root user",
					Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
					Remediation: "Set securityContext.runAsNonRoot: true",
				}
			}
		} else {
			return &types.Violation{
				RuleID:      "SEC-003",
				Severity:    "medium",
				Description:     "Missing security context for non-root enforcement",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Add securityContext with runAsNonRoot: true",
			}
		}
	}

	return nil
}

// checkReadOnlyRootFS checks for read-only root filesystem
func (s *Scanner) checkReadOnlyRootFS(resource K8sResource) *types.Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if readOnlyRootFS, ok := securityContext["readOnlyRootFilesystem"].(bool); !ok || !readOnlyRootFS {
				return &types.Violation{
					RuleID:      "SEC-004",
					Severity:    "medium",
					Description:     "Container filesystem is not read-only",
					Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
					Remediation: "Set securityContext.readOnlyRootFilesystem: true",
				}
			}
		}
	}

	return nil
}

// checkSecurityContext checks for comprehensive security context
func (s *Scanner) checkSecurityContext(resource K8sResource) *types.Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		if _, ok := container["securityContext"]; !ok {
			return &types.Violation{
				RuleID:      "SEC-005",
				Severity:    "low",
				Description:     "Container missing security context",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Add comprehensive securityContext with appropriate settings",
			}
		}
	}

	return nil
}

// Helper functions

func (s *Scanner) parseYAML(content []byte) ([]K8sResource, error) {
	resources := []K8sResource{}
	
	// Split multi-document YAML
	docs := strings.Split(string(content), "---")
	
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		
		var resource K8sResource
		if err := yaml.Unmarshal([]byte(doc), &resource); err != nil {
			return nil, err
		}
		
		resources = append(resources, resource)
	}
	
	return resources, nil
}

func (s *Scanner) getContainers(resource K8sResource) []map[string]interface{} {
	containers := []map[string]interface{}{}

	// Handle Pod
	if resource.Kind == "Pod" {
		if containersList, ok := resource.Spec["containers"].([]interface{}); ok {
			for _, c := range containersList {
				if container, ok := c.(map[string]interface{}); ok {
					containers = append(containers, container)
				}
			}
		}
	}

	// Handle Deployment
	if resource.Kind == "Deployment" {
		if template, ok := resource.Spec["template"].(map[string]interface{}); ok {
			if spec, ok := template["spec"].(map[string]interface{}); ok {
				if containersList, ok := spec["containers"].([]interface{}); ok {
					for _, c := range containersList {
						if container, ok := c.(map[string]interface{}); ok {
							containers = append(containers, container)
						}
					}
				}
			}
		}
	}

	return containers
}

func (s *Scanner) getResourceName(resource K8sResource) string {
	if name, ok := resource.Metadata["name"].(string); ok {
		return name
	}
	return "unknown"
}

func (s *Scanner) discoverManifests(path string) ([]string, error) {
	var files []string

	matches, err := filepath.Glob(filepath.Join(path, "*.yaml"))
	if err != nil {
		return nil, err
	}
	files = append(files, matches...)

	matches, err = filepath.Glob(filepath.Join(path, "*.yml"))
	if err != nil {
		return nil, err
	}
	files = append(files, matches...)

	return files, nil
}
