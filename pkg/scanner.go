package static

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scanner handles static analysis of Kubernetes manifests
type Scanner struct {
	RulesEngine *RulesEngine
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
	Violations []Violation         `json:"violations"`
	Metadata   map[string]string   `json:"metadata"`
	Passed     bool                `json:"passed"`
}

// Violation represents a security violation found during scanning
type Violation struct {
	RuleID      string   `json:"rule_id"`
	Severity    string   `json:"severity"`
	Message     string   `json:"message"`
	Resource    string   `json:"resource"`
	LineNumber  int      `json:"line_number"`
	Remediation string   `json:"remediation"`
}

// K8sResource represents a parsed Kubernetes resource
type K8sResource struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   map[string]interface{} `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
}

// NewScanner creates a new static scanner instance
func NewScanner(config *ScanConfig) (*Scanner, error) {
	rulesEngine, err := NewRulesEngine(config.RulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rules engine: %w", err)
	}

	return &Scanner{
		RulesEngine: rulesEngine,
		Config:      config,
	}, nil
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

	return results, nil
}

// ScanFile scans a single manifest file
func (s *Scanner) ScanFile(filePath string) (ScanResult, error) {
	result := ScanResult{
		FilePath:   filePath,
		Violations: []Violation{},
		Metadata:   make(map[string]string),
		Passed:     true,
	}

	// Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return result, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse YAML documents (handle multi-doc YAML)
	resources, err := s.parseYAML(content)
	if err != nil {
		return result, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Scan each resource
	for _, resource := range resources {
		violations := s.scanResource(resource)
		result.Violations = append(result.Violations, violations...)
	}

	// Set metadata
	if len(resources) > 0 {
		result.Metadata["kind"] = resources[0].Kind
		if name, ok := resources[0].Metadata["name"].(string); ok {
			result.Metadata["name"] = name
		}
	}

	// Determine if scan passed
	result.Passed = len(result.Violations) == 0

	return result, nil
}

// scanResource applies all rules to a single resource
func (s *Scanner) scanResource(resource K8sResource) []Violation {
	violations := []Violation{}

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
	customViolations := s.RulesEngine.Apply(resource)
	violations = append(violations, customViolations...)

	return violations
}

// checkPrivilegedContainers checks for privileged container configurations
func (s *Scanner) checkPrivilegedContainers(resource K8sResource) *Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	// Navigate to containers spec
	containers := s.getContainers(resource)
	for _, container := range containers {
		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if privileged, ok := securityContext["privileged"].(bool); ok && privileged {
				return &Violation{
					RuleID:      "SEC-001",
					Severity:    "critical",
					Message:     "Privileged container detected",
					Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
					Remediation: "Remove 'privileged: true' from securityContext or set to false",
				}
			}
		}
	}

	return nil
}

// checkResourceLimits checks for missing CPU/memory limits
func (s *Scanner) checkResourceLimits(resource K8sResource) *Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		resources, ok := container["resources"].(map[string]interface{})
		if !ok {
			return &Violation{
				RuleID:      "SEC-002",
				Severity:    "high",
				Message:     "Container missing resource limits",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Add resources.limits.cpu and resources.limits.memory to container spec",
			}
		}

		limits, ok := resources["limits"].(map[string]interface{})
		if !ok || limits["cpu"] == nil || limits["memory"] == nil {
			return &Violation{
				RuleID:      "SEC-002",
				Severity:    "high",
				Message:     "Container missing CPU or memory limits",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Define both CPU and memory limits in resources.limits",
			}
		}
	}

	return nil
}

// checkNonRootUser checks if containers run as non-root
func (s *Scanner) checkNonRootUser(resource K8sResource) *Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if runAsNonRoot, ok := securityContext["runAsNonRoot"].(bool); !ok || !runAsNonRoot {
				return &Violation{
					RuleID:      "SEC-003",
					Severity:    "medium",
					Message:     "Container may run as root user",
					Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
					Remediation: "Set securityContext.runAsNonRoot: true",
				}
			}
		} else {
			return &Violation{
				RuleID:      "SEC-003",
				Severity:    "medium",
				Message:     "Missing security context for non-root enforcement",
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
				Remediation: "Add securityContext with runAsNonRoot: true",
			}
		}
	}

	return nil
}

// checkReadOnlyRootFS checks for read-only root filesystem
func (s *Scanner) checkReadOnlyRootFS(resource K8sResource) *Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if readOnlyRootFS, ok := securityContext["readOnlyRootFilesystem"].(bool); !ok || !readOnlyRootFS {
				return &Violation{
					RuleID:      "SEC-004",
					Severity:    "medium",
					Message:     "Container filesystem is not read-only",
					Resource:    fmt.Sprintf("%s/%s", resource.Kind, s.getResourceName(resource)),
					Remediation: "Set securityContext.readOnlyRootFilesystem: true",
				}
			}
		}
	}

	return nil
}

// checkSecurityContext checks for comprehensive security context
func (s *Scanner) checkSecurityContext(resource K8sResource) *Violation {
	if resource.Kind != "Pod" && resource.Kind != "Deployment" {
		return nil
	}

	containers := s.getContainers(resource)
	for _, container := range containers {
		if _, ok := container["securityContext"]; !ok {
			return &Violation{
				RuleID:      "SEC-005",
				Severity:    "low",
				Message:     "Container missing security context",
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
