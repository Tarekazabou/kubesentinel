package types

type Violation struct {
	// Violation is the canonical manifest finding contract shared by the Go
	// and Python scanners.
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Path        string `json:"path,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	LineNumber  int      `json:"line_number,omitempty"`
	Compliance  []string `json:"compliance,omitempty"`
}
