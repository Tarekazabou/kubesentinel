package static

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RulesEngine manages and applies security rules
type RulesEngine struct {
	Rules []Rule
}

// Rule represents a security rule
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Kind        []string `yaml:"kind"`
	Checks      []Check  `yaml:"checks"`
	Remediation string   `yaml:"remediation"`
}

// Check represents a specific condition to validate
type Check struct {
	Path     string      `yaml:"path"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value"`
}

// NewRulesEngine creates a new rules engine
func NewRulesEngine(rulesPath string) (*RulesEngine, error) {
	engine := &RulesEngine{
		Rules: []Rule{},
	}

	if err := engine.loadRules(rulesPath); err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	return engine, nil
}

// loadRules loads all rule files from the given path
func (re *RulesEngine) loadRules(rulesPath string) error {
	files, err := filepath.Glob(filepath.Join(rulesPath, "*.yaml"))
	if err != nil {
		return err
	}

	for _, file := range files {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read rule file %s: %w", file, err)
		}

		var rules []Rule
		if err := yaml.Unmarshal(content, &rules); err != nil {
			return fmt.Errorf("failed to parse rule file %s: %w", file, err)
		}

		re.Rules = append(re.Rules, rules...)
	}

	return nil
}

// Apply applies all relevant rules to a resource
func (re *RulesEngine) Apply(resource K8sResource) []Violation {
	violations := []Violation{}

	for _, rule := range re.Rules {
		// Check if rule applies to this resource kind
		if !re.appliesToKind(rule, resource.Kind) {
			continue
		}

		// Check all conditions
		if re.checkRule(rule, resource) {
			violations = append(violations, Violation{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Message:     rule.Description,
				Resource:    fmt.Sprintf("%s/%s", resource.Kind, getNameFromMetadata(resource.Metadata)),
				Remediation: rule.Remediation,
			})
		}
	}

	return violations
}

// appliesToKind checks if a rule applies to a specific resource kind
func (re *RulesEngine) appliesToKind(rule Rule, kind string) bool {
	if len(rule.Kind) == 0 {
		return true // Apply to all kinds
	}

	for _, k := range rule.Kind {
		if k == kind || k == "*" {
			return true
		}
	}

	return false
}

// checkRule evaluates all checks for a rule
func (re *RulesEngine) checkRule(rule Rule, resource K8sResource) bool {
	for _, check := range rule.Checks {
		if !re.evaluateCheck(check, resource) {
			return false // All checks must pass
		}
	}
	return len(rule.Checks) > 0 // At least one check must exist
}

// evaluateCheck evaluates a single check against a resource
func (re *RulesEngine) evaluateCheck(check Check, resource K8sResource) bool {
	// Get value at path
	value := re.getValueAtPath(check.Path, resource)

	// Evaluate based on operator
	switch check.Operator {
	case "equals":
		return value == check.Value
	case "notEquals":
		return value != check.Value
	case "exists":
		return value != nil
	case "notExists":
		return value == nil
	case "contains":
		if strVal, ok := value.(string); ok {
			if checkVal, ok := check.Value.(string); ok {
				return contains(strVal, checkVal)
			}
		}
		return false
	case "greaterThan":
		return compareNumbers(value, check.Value, ">")
	case "lessThan":
		return compareNumbers(value, check.Value, "<")
	default:
		return false
	}
}

// getValueAtPath navigates through nested maps to get value at path
func (re *RulesEngine) getValueAtPath(path string, resource K8sResource) interface{} {
	// Split path by dots
	parts := splitPath(path)
	
	var current interface{} = map[string]interface{}{
		"apiVersion": resource.APIVersion,
		"kind":       resource.Kind,
		"metadata":   resource.Metadata,
		"spec":       resource.Spec,
	}

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case map[interface{}]interface{}:
			current = v[part]
		default:
			return nil
		}

		if current == nil {
			return nil
		}
	}

	return current
}

// Helper functions

func getNameFromMetadata(metadata map[string]interface{}) string {
	if name, ok := metadata["name"].(string); ok {
		return name
	}
	return "unknown"
}

func splitPath(path string) []string {
	// Simple path splitter - in production, handle more complex cases
	parts := []string{}
	current := ""
	
	for _, char := range path {
		if char == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	
	if current != "" {
		parts = append(parts, current)
	}
	
	return parts
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s != substr && 
		(len(s) == 0 || len(substr) == 0 || s[0:len(substr)] == substr || contains(s[1:], substr))
}

func compareNumbers(a, b interface{}, op string) bool {
	var aNum, bNum float64

	switch v := a.(type) {
	case int:
		aNum = float64(v)
	case float64:
		aNum = v
	default:
		return false
	}

	switch v := b.(type) {
	case int:
		bNum = float64(v)
	case float64:
		bNum = v
	default:
		return false
	}

	switch op {
	case ">":
		return aNum > bNum
	case "<":
		return aNum < bNum
	case ">=":
		return aNum >= bNum
	case "<=":
		return aNum <= bNum
	default:
		return false
	}
}
