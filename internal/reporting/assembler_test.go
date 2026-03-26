package reporting

import (
	"kubesentinel/internal/forensics"
	"testing"
	"time"
)

func TestBuildReport_DeterministicCoreSections(t *testing.T) {
	now := time.Now().UTC()
	records := []forensics.ForensicRecord{
		{
			ID:           "rec-1",
			Timestamp:    now.Add(-2 * time.Minute),
			IncidentType: "Terminal shell in container",
			Severity:     "high",
			RiskScore:    0.82,
			Container:    forensics.ContainerContext{Name: "api-pod"},
			Events:       []forensics.SecurityEvent{{Timestamp: now.Add(-2 * time.Minute), Output: "shell spawned"}},
		},
		{
			ID:           "rec-2",
			Timestamp:    now.Add(-1 * time.Minute),
			IncidentType: "Sensitive file opened for reading",
			Severity:     "critical",
			RiskScore:    0.97,
			Container:    forensics.ContainerContext{Name: "worker-pod"},
			Events:       []forensics.SecurityEvent{{Timestamp: now.Add(-1 * time.Minute), Output: "shadow read"}},
		},
	}

	report := BuildReport(records, now.Add(-10*time.Minute), now)

	if report.Summary.TotalIncidents != 2 {
		t.Fatalf("expected 2 incidents, got %d", report.Summary.TotalIncidents)
	}
	if report.Summary.CriticalIncidents != 1 {
		t.Fatalf("expected 1 critical incident, got %d", report.Summary.CriticalIncidents)
	}
	if len(report.Timeline) != 2 {
		t.Fatalf("expected 2 timeline events, got %d", len(report.Timeline))
	}
	if report.Statistics.TotalEvents != len(report.Timeline) {
		t.Fatalf("expected stats total events to equal timeline size")
	}
	if report.Summary.OverallRisk != "critical" {
		t.Fatalf("expected overall risk critical, got %q", report.Summary.OverallRisk)
	}
}
