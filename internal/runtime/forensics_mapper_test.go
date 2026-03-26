package runtime

import (
	"testing"
	"time"
)

func TestBuildForensicRecord_MapsCoreFields(t *testing.T) {
	now := time.Now().UTC()
	eventTime := now.Add(-1 * time.Minute)

	event := SecurityEvent{
		Timestamp: eventTime,
		Priority:  "Critical",
		Rule:      "Sensitive file opened for reading",
		Output:    "An access to /etc/shadow was detected",
		Source:    "falco",
		Fields: map[string]interface{}{
			"proc.name":    "cat",
			"proc.pid":     4242,
			"proc.cmdline": "cat /etc/shadow",
			"fd.name":      "/etc/shadow",
			"fd.sip":       "10.1.1.2",
			"fd.dip":       "10.1.2.3",
			"fd.sport":     49752,
			"fd.dport":     443,
			"evt.type":     "openat",
		},
		Container: ContainerInfo{
			ID:        "container-1",
			Name:      "api",
			Image:     "myrepo/api:latest",
			Namespace: "prod",
			PodName:   "api-7c54d77f7c-abcde",
		},
	}

	features := BehavioralFeatures{
		ProcessName:      "cat",
		CommandLine:      "cat /etc/shadow",
		ParentProcess:    "bash",
		UserID:           "0",
		ProcessFrequency: 3,
		FileAccessCount:  1,
		NetworkConnCount: 0,
		SensitiveFiles:   []string{"/etc/shadow"},
		Namespace:        "prod",
		ContainerID:      "container-1",
		TimeWindow:       "night",
		TimeOfDay:        2,
		DayOfWeek:        4,
		ContainerAge:     120,
	}

	record := buildForensicRecord(event, features, 0.92, now)

	if record.Timestamp != eventTime {
		t.Fatalf("expected timestamp %v, got %v", eventTime, record.Timestamp)
	}
	if record.Severity != "critical" {
		t.Fatalf("expected critical severity, got %q", record.Severity)
	}
	if record.RiskScore != 0.92 {
		t.Fatalf("expected risk score 0.92, got %v", record.RiskScore)
	}
	if len(record.Events) != 1 || record.Events[0].Rule != event.Rule {
		t.Fatalf("expected one mapped event with rule %q", event.Rule)
	}
	if got := record.Metadata["process_name"]; got != "cat" {
		t.Fatalf("expected process_name metadata 'cat', got %#v", got)
	}
	if got := record.Container.Namespace; got != "prod" {
		t.Fatalf("expected namespace 'prod', got %q", got)
	}
	if len(record.SystemCalls) == 0 || record.SystemCalls[0].Name != "openat" {
		t.Fatalf("expected syscall evidence from evt.type, got %#v", record.SystemCalls)
	}
	if len(record.FileOperations) == 0 || record.FileOperations[0].FilePath != "/etc/shadow" {
		t.Fatalf("expected file operation evidence from fd.name, got %#v", record.FileOperations)
	}
	if len(record.NetworkTraces) == 0 || record.NetworkTraces[0].SourceIP != "10.1.1.2" {
		t.Fatalf("expected network trace evidence from fd.sip/fd.dip, got %#v", record.NetworkTraces)
	}
}

func TestBuildForensicRecord_FallbackTimestamp(t *testing.T) {
	processedAt := time.Now().UTC()
	event := SecurityEvent{Priority: "Notice"}
	features := BehavioralFeatures{}

	record := buildForensicRecord(event, features, 0.5, processedAt)

	if !record.Timestamp.Equal(processedAt) {
		t.Fatalf("expected fallback timestamp %v, got %v", processedAt, record.Timestamp)
	}
	if record.Severity != "medium" {
		t.Fatalf("expected medium severity for notice, got %q", record.Severity)
	}
}
