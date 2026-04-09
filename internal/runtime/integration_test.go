//go:build integration
// +build integration

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
	resp, err := client.DetectAnomaly(context.Background(), testVec)
	if err != nil {
		t.Fatalf("DetectAnomaly failed: %v", err)
	}

	latency := time.Since(start).Milliseconds()
	if latency > 100 {
		t.Logf("⚠️  AI response took %d ms (should be < 100 ms)", latency)
	}

	if resp.Score < 0 || resp.Score > 1 {
		t.Errorf("Score out of range: %f", resp.Score)
	}

	t.Logf("✅ AI integration OK | Score=%.3f | Reason=%s | Latency=%d ms",
		resp.Score, resp.Reason, latency)
}
