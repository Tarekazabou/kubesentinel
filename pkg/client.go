package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// Client handles communication with the AI/ML service
type Client struct {
	Endpoint   string
	HTTPClient *http.Client
	Threshold  float64
}

// AnomalyRequest represents a request to the AI service
type AnomalyRequest struct {
	Features  FeatureVector `json:"features"`
	Context   string        `json:"context"`
	Timestamp string        `json:"timestamp"`
}

// AnomalyResponse represents a response from the AI service
type AnomalyResponse struct {
	IsAnomaly   bool    `json:"is_anomaly"`
	Score       float64 `json:"score"`
	Confidence  float64 `json:"confidence"`
	Reason      string  `json:"reason"`
	Suggestions []string `json:"suggestions"`
}

// FeatureVector represents the behavioral features for ML analysis
type FeatureVector struct {
	ProcessName      string         `json:"process_name"`
	ProcessFrequency int            `json:"process_frequency"`
	SyscallCounts    map[string]int `json:"syscall_counts"`
	FileAccessCount  int            `json:"file_access_count"`
	NetworkCount     int            `json:"network_count"`
	SensitiveFiles   int            `json:"sensitive_files"`
	UserID           string         `json:"user_id"`
	TimeOfDay        int            `json:"time_of_day"`
	DayOfWeek        int            `json:"day_of_week"`
	ContainerAge     int            `json:"container_age"`
}

// NewClient creates a new AI client
func NewClient(endpoint string, threshold float64) *Client {
	return &Client{
		Endpoint:  endpoint,
		Threshold: threshold,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// DetectAnomaly sends features to AI service for anomaly detection
func (c *Client) DetectAnomaly(ctx context.Context, features FeatureVector) (*AnomalyResponse, error) {
	// Prepare request
	request := AnomalyRequest{
		Features:  features,
		Context:   "runtime-monitoring",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", 
		fmt.Sprintf("%s/predict", c.Endpoint), 
		bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("AI service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response AnomalyResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// HealthCheck checks if the AI service is healthy
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", 
		fmt.Sprintf("%s/health", c.Endpoint), nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AI service unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// UpdateBaseline sends new training data to update the baseline model
func (c *Client) UpdateBaseline(ctx context.Context, trainingData []FeatureVector) error {
	// Marshal training data
	jsonData, err := json.Marshal(map[string]interface{}{
		"training_data": trainingData,
		"timestamp":     time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal training data: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/train", c.Endpoint),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("training failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetModelInfo retrieves information about the current model
func (c *Client) GetModelInfo(ctx context.Context) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/model/info", c.Endpoint), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var info map[string]interface{}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return info, nil
}
