package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"kubesentinel/internal/forensics"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type GeminiConfig struct {
	Enabled        bool
	APIKey         string
	Model          string
	TimeoutSeconds int
}

type GeminiClient struct {
	config     GeminiConfig
	httpClient *http.Client
}

func NewGeminiClient(config GeminiConfig) *GeminiClient {
	timeout := config.TimeoutSeconds
	if timeout <= 0 {
		timeout = 15
	}
	if strings.TrimSpace(config.Model) == "" {
		config.Model = "gemini-2.5-flash"
	}
	return &GeminiClient{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

type GeminiNarrative struct {
	Narrative       string   `json:"narrative"`
	Findings        []string `json:"findings"`
	Recommendations []string `json:"recommendations"`
}

type IncidentClassification struct {
	IncidentType string  `json:"incident_type"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

func (c *GeminiClient) Enabled() bool {
	return c != nil && c.config.Enabled && strings.TrimSpace(c.config.APIKey) != ""
}

func (c *GeminiClient) GenerateNarrative(ctx context.Context, prompt string) (GeminiNarrative, error) {
	if !c.Enabled() {
		return GeminiNarrative{}, fmt.Errorf("gemini disabled")
	}

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{{"text": prompt}},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":      0.2,
			"responseMimeType": "application/json",
		},
	}

	payload, err := json.Marshal(requestBody)
	if err != nil {
		return GeminiNarrative{}, err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", c.config.Model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return GeminiNarrative{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Pass API key as a header to avoid credential exposure in access logs and proxy logs.
	req.Header.Set("x-goog-api-key", c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return GeminiNarrative{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GeminiNarrative{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GeminiNarrative{}, fmt.Errorf("gemini request failed: %s", strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return GeminiNarrative{}, err
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return GeminiNarrative{}, fmt.Errorf("gemini empty response")
	}

	rawText := parsed.Candidates[0].Content.Parts[0].Text
	var narrative GeminiNarrative
	if err := json.Unmarshal([]byte(rawText), &narrative); err == nil {
		return narrative, nil
	}

	// Fallback for non-JSON responses.
	return GeminiNarrative{Narrative: rawText}, nil
}

func (c *GeminiClient) ClassifyRecord(ctx context.Context, record forensics.ForensicRecord) (IncidentClassification, error) {
	if !c.Enabled() {
		return IncidentClassification{}, fmt.Errorf("gemini disabled")
	}

	summary := map[string]interface{}{
		"timestamp":     record.Timestamp,
		"severity":      record.Severity,
		"risk_score":    record.RiskScore,
		"incident_type": record.IncidentType,
		"container": map[string]string{
			"name":      record.Container.Name,
			"namespace": record.Container.Namespace,
			"pod_name":  record.Container.PodName,
			"image":     record.Container.Image,
		},
	}

	if len(record.Events) > 0 {
		event := record.Events[0]
		summary["trigger_event"] = map[string]interface{}{
			"rule":     event.Rule,
			"priority": event.Priority,
			"output":   sanitizeGeminiText(event.Output),
			"fields":   sanitizeFields(event.Fields),
		}
	}

	payload, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return IncidentClassification{}, err
	}

	prompt := "Classify this Kubernetes security incident. Return JSON only with keys: incident_type (string), confidence (number 0..1), reason (string). Input:\n" + string(payload)

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{
			"temperature":      0.1,
			"responseMimeType": "application/json",
		},
	}

	requestPayload, err := json.Marshal(requestBody)
	if err != nil {
		return IncidentClassification{}, err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", c.config.Model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestPayload))
	if err != nil {
		return IncidentClassification{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Pass API key as a header to avoid credential exposure in access logs and proxy logs.
	req.Header.Set("x-goog-api-key", c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return IncidentClassification{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return IncidentClassification{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IncidentClassification{}, fmt.Errorf("gemini classification failed: %s", strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return IncidentClassification{}, err
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return IncidentClassification{}, fmt.Errorf("gemini classification empty response")
	}

	rawText := parsed.Candidates[0].Content.Parts[0].Text
	classification := IncidentClassification{}
	if err := json.Unmarshal([]byte(rawText), &classification); err != nil {
		classification = IncidentClassification{
			IncidentType: strings.TrimSpace(rawText),
			Confidence:   0.5,
			Reason:       "Gemini returned unstructured classification text",
		}
	}

	if classification.Confidence < 0 {
		classification.Confidence = 0
	}
	if classification.Confidence > 1 {
		classification.Confidence = 1
	}
	return classification, nil
}

var geminiSensitiveRegex = regexp.MustCompile(`(?i)(token|secret|password|apikey|api_key|bearer)\s*[=:]\s*[^\s]+`)

func sanitizeGeminiText(input string) string {
	if strings.TrimSpace(input) == "" {
		return input
	}
	return geminiSensitiveRegex.ReplaceAllString(input, "$1=[REDACTED]")
}

func sanitizeFields(fields map[string]interface{}) map[string]interface{} {
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
	}
	out := map[string]interface{}{}
	for key, value := range fields {
		if _, ok := allowed[key]; !ok {
			continue
		}
		if text, ok := value.(string); ok {
			out[key] = sanitizeGeminiText(text)
		} else {
			out[key] = value
		}
	}
	return out
}
