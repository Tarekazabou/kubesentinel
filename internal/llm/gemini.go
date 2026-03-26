package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		config.Model = "gemini-1.5-flash"
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

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.config.Model, c.config.APIKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return GeminiNarrative{}, err
	}
	req.Header.Set("Content-Type", "application/json")

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
