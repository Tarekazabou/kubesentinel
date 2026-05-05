package runtime

import (
	"context"
	"testing"
	"time"

	"kubesentinel/internal/ai"
)

func TestAIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := ai.NewClient("http://localhost:5000", 0.75)

	// Health check
	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("AI service not reachable. Start it with: make run-ai\nError: %v", err)
	}

	// Real feature vector (matches your Python model)
	testVec := ai.FeatureVector{
		ProcessName:      "cat",
		ProcessFrequency: 5,
		FileAccessCount:  120,
		NetworkCount:     3,
		SensitiveFiles:   1,
		UserID:           "0",
		TimeOfDay:        3,
		DayOfWeek:        6,
		ContainerAge:     300,
	}

	start := time.Now()
	// Test 1: Pass nil for incident payload (fallback/legacy mode)
	resp, err := client.DetectAnomaly(context.Background(), testVec, nil)
	if err != nil {
		t.Fatalf("DetectAnomaly failed without incident payload: %v", err)
	}

	latency := time.Since(start).Milliseconds()
	if latency > 100 {
		t.Logf("⚠️  AI response took %d ms (should be < 100 ms)", latency)
	}

	if resp.Score < 0 || resp.Score > 1 {
		t.Errorf("Score out of range: %f", resp.Score)
	}

	t.Logf("✅ AI integration OK (No Incident) | Score=%.3f | Reason=%s | Latency=%d ms",
		resp.Score, resp.Reason, latency)

	// Test 2: Include a valid incident payload to test staging logic
	dummyIncident := map[string]interface{}{
		"id":            "test-incident-integration",
		"timestamp":     time.Now().Format(time.RFC3339),
		"incident_type": "TestAnomaly",
		"severity":      "high",
		"risk_score":    0.99,
		"description":   "Integration test anomaly",
		"container": map[string]string{
			"id":        "container-uuid",
			"name":      "test-container",
			"pod_name":  "test-pod",
			"namespace": "default",
		},
		"metadata": map[string]interface{}{
			"process_name":      "cat",
			"process_frequency": 5,
			"file_access_count": 120,
			"network_count":     3,
			"sensitive_files":   1,
			"time_of_day":       3,
			"day_of_week":       6,
			"container_age":     300,
			"unique_syscalls":   5,
		},
		"events": []map[string]interface{}{
			{
				"timestamp": time.Now().Format(time.RFC3339),
				"rule":      "TestRule",
				"output":    "Test Output",
			},
		},
	}

	respWithIncident, err := client.DetectAnomaly(context.Background(), testVec, dummyIncident)
	if err != nil {
		t.Fatalf("DetectAnomaly failed with incident payload: %v", err)
	}

	if respWithIncident.Score < 0 || respWithIncident.Score > 1 {
		t.Errorf("Score out of range: %f", respWithIncident.Score)
	}

	t.Logf("✅ AI integration OK (With Incident) | Score=%.3f | Reason=%s",
		respWithIncident.Score, respWithIncident.Reason)
}
