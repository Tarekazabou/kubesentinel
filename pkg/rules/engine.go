package rules

import (
	"fmt"
	"kubesentinel/pkg/types"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule ← keep your existing struct
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Kind        []string `yaml:"kind"`
	Checks      []Check  `yaml:"checks"`
	Remediation string   `yaml:"remediation"`
}

type Check struct {
	Path     string      `yaml:"path"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value"`
}

type RulesEngine struct {
	Rules []Rule
}

func getValueAtPath(data map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		if current == nil {
			return nil
		}

		switch v := current.(type) {
		case map[string]interface{}:
			if part == "*" {
				return nil // we don't evaluate inside arrays yet for simplicity
			}
			current = v[part]
		case []interface{}:
			if part != "*" {
				return nil
			}
			// For [*] we return first matching violation later in Apply()
			// For now, we'll handle array iteration in Apply()
			return nil
		default:
			return nil
		}
	}
	return current
}
func (e *RulesEngine) ListRules() []Rule { return e.Rules }
func NewRulesEngine(rulesDir string) (*RulesEngine, error) {
	engine := &RulesEngine{}

	if err := engine.LoadRules(rulesDir); err != nil {
		return nil, err
	}

	return engine, nil
}

// LoadRules reads all YAML rule files from the given directory and replaces
// the current rule set. It is called by NewRulesEngine and can be called
// again at runtime to hot-reload rules.
func (e *RulesEngine) LoadRules(rulesDir string) error {
	files, err := os.ReadDir(rulesDir)
	if err != nil {
		return err
	}

	var allRules []Rule
	for _, file := range files {
		if file.IsDir() || !isYamlFile(file.Name()) {
			continue
		}

		path := filepath.Join(rulesDir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return fmt.Errorf("invalid yaml in %s: %w", path, err)
		}

		allRules = append(allRules, rules...)
	}

	e.Rules = allRules
	return nil
}

func (e *RulesEngine) Apply(resource map[string]interface{}) []types.Violation {
	var violations []types.Violation

	for _, rule := range e.Rules {
		// Very basic kind filtering (you can make it better later)
		if !kindMatches(rule.Kind, resource) {
			continue
		}

		for _, check := range rule.Checks {
			if strings.Contains(check.Path, "[*]") {
				if violated := checkArray(resource, check); violated {
					violations = append(violations, types.Violation{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Description: rule.Description,
						Remediation: rule.Remediation,
						Path:        check.Path,
					})
				}
			} else {
				if violatesCheck(resource, check) {
					violations = append(violations, types.Violation{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Description: rule.Description,
						Remediation: rule.Remediation,
						Path:        check.Path,
					})
				}
			}
		}
	}
	return violations
}
func checkArray(resource map[string]interface{}, check Check) bool {
	basePath := strings.Replace(check.Path, "[*]", "", 1)
	parts := strings.Split(basePath, ".")
	var array []interface{}

	// Navigate to the array
	current := interface{}(resource)
	for i, part := range parts {
		if i == len(parts)-1 { // last part should be the array
			if m, ok := current.(map[string]interface{}); ok {
				array, _ = m[part].([]interface{})
			}
			break
		}
		if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else {
			return false
		}
	}

	if array == nil {
		return false
	}

	// Check each item in array
	for _, item := range array {
		if itemMap, ok := item.(map[string]interface{}); ok {
			subCheck := check
			subCheck.Path = strings.TrimPrefix(check.Path, strings.Split(check.Path, "[*]")[0])
			if violatesCheck(itemMap, subCheck) {
				return true // one violation is enough
			}
		}
	}
	return false
}

// You need these helper functions — add them if missing
func isYamlFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yaml" || ext == ".yml"
}

func kindMatches(kinds []string, resource map[string]interface{}) bool {
	kind, _ := resource["kind"].(string)
	for _, k := range kinds {
		if k == kind || k == "*" {
			return true
		}
	}
	return len(kinds) == 0
}

// violatesCheck evaluates if a check condition is violated in the resource
func violatesCheck(resource map[string]interface{}, check Check) bool {
	actualValue := getValueAtPath(resource, check.Path)

	// If path doesn't exist → depends on operator
	if actualValue == nil {
		if check.Operator == "exists" {
			return false // path doesn't exist → "exists" check is not violated
		}
		if check.Operator == "notExists" {
			return true // path doesn't exist → "notExists" check IS violated (condition met)
		}
		return false
	}

	switch check.Operator {
	case "equals":
		return actualValue == check.Value
	case "notEquals":
		return actualValue != check.Value
	case "contains":
		if s, ok := actualValue.(string); ok {
			if target, ok := check.Value.(string); ok {
				return strings.Contains(s, target)
			}
		}
		return false
	case "exists":
		return true // path exists
	case "notExists":
		return false // path exists → not violated
	case "greaterThan":
		if aNum, ok := actualValue.(float64); ok {
			if bNum, ok := check.Value.(float64); ok {
				return aNum > bNum
			}
		}
		return false
	case "lessThan":
		if aNum, ok := actualValue.(float64); ok {
			if bNum, ok := check.Value.(float64); ok {
				return aNum < bNum
			}
		}
		return false
	case "greaterThanOrEquals":
		if aNum, ok := actualValue.(float64); ok {
			if bNum, ok := check.Value.(float64); ok {
				return aNum >= bNum
			}
		}
		return false
	case "lessThanOrEquals":
		if aNum, ok := actualValue.(float64); ok {
			if bNum, ok := check.Value.(float64); ok {
				return aNum <= bNum
			}
		}
		return false
		// Add similar for ">=", "<="
	default:
		return false
	}
}
