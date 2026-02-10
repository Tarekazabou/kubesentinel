package types

type Violation struct {
    RuleID      string `json:"rule_id"`
    Severity    string `json:"severity"`
    Description string `json:"description"`     // ← added
    Remediation string `json:"remediation"`
    Path        string `json:"path,omitempty"`  // ← added
    Resource    string `json:"resource,omitempty"`
    LineNumber  int    `json:"line_number,omitempty"`
}