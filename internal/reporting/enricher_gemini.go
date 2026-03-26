package reporting

import (
	"context"
	"encoding/json"
	"kubesentinel/internal/forensics"
	"kubesentinel/internal/llm"
	"regexp"
	"strings"
)

type GeminiEnricher struct {
	client *llm.GeminiClient
}

func NewGeminiEnricher(client *llm.GeminiClient) *GeminiEnricher {
	return &GeminiEnricher{client: client}
}

func (g *GeminiEnricher) EnrichReport(ctx context.Context, report Report, records []forensics.ForensicRecord) (Report, error) {
	if g == nil || g.client == nil || !g.client.Enabled() {
		return report, nil
	}

	prompt, err := buildGeminiPrompt(report, records)
	if err != nil {
		return report, err
	}

	result, err := g.client.GenerateNarrative(ctx, prompt)
	if err != nil {
		return report, err
	}

	if strings.TrimSpace(result.Narrative) != "" {
		report.Narrative = result.Narrative
	}
	if len(result.Findings) > 0 {
		report.LLMFindings = result.Findings
	}
	for _, recommendation := range result.Recommendations {
		if strings.TrimSpace(recommendation) == "" {
			continue
		}
		report.LLMRecommendations = append(report.LLMRecommendations, Recommendation{
			Priority:    "medium",
			Title:       "Gemini recommendation",
			Description: recommendation,
			Impact:      "medium",
			Effort:      "medium",
		})
	}

	return report, nil
}

func buildGeminiPrompt(report Report, records []forensics.ForensicRecord) (string, error) {
	type promptInput struct {
		Report  Report                     `json:"report"`
		Records []forensics.ForensicRecord `json:"records"`
	}

	redacted := make([]forensics.ForensicRecord, 0, len(records))
	for _, record := range records {
		clone := record
		for index := range clone.Events {
			clone.Events[index].Output = redactSensitiveText(clone.Events[index].Output)
			clone.Events[index].Fields = filterAllowedFields(clone.Events[index].Fields)
		}
		if clone.Metadata != nil {
			for key, value := range clone.Metadata {
				if strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "secret") {
					clone.Metadata[key] = "[REDACTED]"
					continue
				}
				if text, ok := value.(string); ok {
					clone.Metadata[key] = redactSensitiveText(text)
				}
			}
		}
		redacted = append(redacted, clone)
	}

	payload, err := json.MarshalIndent(promptInput{Report: report, Records: redacted}, "", "  ")
	if err != nil {
		return "", err
	}

	prompt := "You are a cloud security incident analyst. Return JSON only with keys: narrative (string), findings (array of strings), recommendations (array of strings). Focus on investigation narrative, likely root causes, and remediation priorities. Input:\n" + string(payload)
	return prompt, nil
}

var (
	tokenRegex = regexp.MustCompile(`(?i)(token|secret|password|apikey|api_key|bearer)\s*[=:]\s*[^\s]+`)
	hexRegex   = regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`)
)

func redactSensitiveText(input string) string {
	if strings.TrimSpace(input) == "" {
		return input
	}
	out := tokenRegex.ReplaceAllString(input, "$1=[REDACTED]")
	out = hexRegex.ReplaceAllString(out, "[REDACTED_HEX]")
	return out
}

func filterAllowedFields(fields map[string]interface{}) map[string]interface{} {
	if fields == nil {
		return nil
	}
	allowed := map[string]struct{}{
		"proc.name":    {},
		"proc.cmdline": {},
		"proc.pname":   {},
		"proc.pid":     {},
		"fd.name":      {},
		"fd.sip":       {},
		"fd.dip":       {},
		"fd.sport":     {},
		"fd.dport":     {},
		"evt.type":     {},
		"evt.time":     {},
	}
	filtered := make(map[string]interface{})
	for key, value := range fields {
		if _, ok := allowed[key]; !ok {
			continue
		}
		if text, ok := value.(string); ok {
			filtered[key] = redactSensitiveText(text)
			continue
		}
		filtered[key] = value
	}
	return filtered
}
