package ai

import (
"context"
"encoding/json"
"net/http"
"net/http/httptest"
"os"
"testing"
"time"
)

func TestDetectAnomaly_SendsAuthorizationHeader(t *testing.T) {
originalToken := os.Getenv("TRAINING_API_TOKEN")
t.Cleanup(func() {
_ = os.Setenv("TRAINING_API_TOKEN", originalToken)
})
_ = os.Setenv("TRAINING_API_TOKEN", "secret-token")

srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.URL.Path != "/predict" {
t.Fatalf("unexpected path: %s", r.URL.Path)
}
if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
t.Fatalf("expected Authorization header, got %q", got)
}
_ = json.NewEncoder(w).Encode(AnomalyResponse{IsAnomaly: false, Score: 0.1, Confidence: 0.9})
}))
defer srv.Close()

client := NewClient(srv.URL, 0.75)
client.HTTPClient = &http.Client{Timeout: 2 * time.Second}

_, err := client.DetectAnomaly(context.Background(), FeatureVector{ProcessFrequency: 1})
if err != nil {
t.Fatalf("DetectAnomaly returned error: %v", err)
}
}

func TestUpdateBaseline_SendsAuthorizationHeader(t *testing.T) {
originalToken := os.Getenv("TRAINING_API_TOKEN")
t.Cleanup(func() {
_ = os.Setenv("TRAINING_API_TOKEN", originalToken)
})
_ = os.Setenv("TRAINING_API_TOKEN", "secret-token")

srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.URL.Path != "/train" {
t.Fatalf("unexpected path: %s", r.URL.Path)
}
if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
t.Fatalf("expected Authorization header, got %q", got)
}
w.WriteHeader(http.StatusOK)
}))
defer srv.Close()

client := NewClient(srv.URL, 0.75)
client.HTTPClient = &http.Client{Timeout: 2 * time.Second}

err := client.UpdateBaseline(context.Background(), []FeatureVector{{ProcessFrequency: 2}})
if err != nil {
t.Fatalf("UpdateBaseline returned error: %v", err)
}
}
