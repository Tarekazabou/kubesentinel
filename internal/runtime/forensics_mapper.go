package runtime

import (
	"fmt"
	"kubesentinel/internal/forensics"
	"strconv"
	"strings"
	"time"
)

// buildForensicRecord maps runtime event + extracted features into a forensics record.
func buildForensicRecord(event SecurityEvent, features BehavioralFeatures, riskScore float64, processedAt time.Time) forensics.ForensicRecord {
	recordTimestamp := event.Timestamp
	if recordTimestamp.IsZero() {
		recordTimestamp = processedAt
	}

	metadata := map[string]interface{}{
		"source":             event.Source,
		"process_name":       features.ProcessName,
		"command_line":       features.CommandLine,
		"parent_process":     features.ParentProcess,
		"user_id":            features.UserID,
		"process_frequency":  features.ProcessFrequency,
		"file_access_count":  features.FileAccessCount,
		"network_conn_count": features.NetworkConnCount,
		"sensitive_files":    features.SensitiveFiles,
		"namespace":          features.Namespace,
		"container_id":       features.ContainerID,
		"time_window":        features.TimeWindow,
		"time_of_day":        features.TimeOfDay,
		"day_of_week":        features.DayOfWeek,
		"container_age":      features.ContainerAge,
	}

	record := forensics.ForensicRecord{
		Timestamp:    recordTimestamp,
		IncidentType: event.Rule,
		Severity:     mapPriorityToSeverity(event.Priority),
		RiskScore:    riskScore,
		Container: forensics.ContainerContext{
			ID:        event.Container.ID,
			Name:      event.Container.Name,
			Image:     event.Container.Image,
			Namespace: event.Container.Namespace,
			PodName:   event.Container.PodName,
			Labels:    map[string]string{},
		},
		Events: []forensics.SecurityEvent{
			{
				Timestamp: recordTimestamp,
				Rule:      event.Rule,
				Priority:  event.Priority,
				Output:    event.Output,
				Fields:    event.Fields,
			},
		},
		Metadata: metadata,
	}

	populateMvpEvidence(&record, event, features, recordTimestamp)
	return record
}

func populateMvpEvidence(record *forensics.ForensicRecord, event SecurityEvent, features BehavioralFeatures, ts time.Time) {
	processName := firstNonEmpty(features.ProcessName, stringField(event.Fields, "proc.name"))
	pid := intField(event.Fields, "proc.pid")

	if syscallName := stringField(event.Fields, "evt.type"); syscallName != "" {
		record.SystemCalls = append(record.SystemCalls, forensics.SystemCall{
			Timestamp: ts,
			Name:      syscallName,
			Process:   processName,
			PID:       pid,
			Args:      []string{stringField(event.Fields, "proc.cmdline")},
			ReturnVal: intField(event.Fields, "evt.res"),
		})
	}

	if fdName := stringField(event.Fields, "fd.name"); fdName != "" {
		record.FileOperations = append(record.FileOperations, forensics.FileOperation{
			Timestamp: ts,
			Operation: inferFileOperation(event.Rule, syscallNameOrDefault(event.Fields)),
			FilePath:  fdName,
			Process:   processName,
			PID:       pid,
			Success:   !strings.Contains(strings.ToLower(event.Output), "denied"),
		})
	}

	srcIP := stringField(event.Fields, "fd.sip")
	dstIP := stringField(event.Fields, "fd.dip")
	if srcIP != "" || dstIP != "" {
		record.NetworkTraces = append(record.NetworkTraces, forensics.NetworkTrace{
			Timestamp:  ts,
			Protocol:   firstNonEmpty(stringField(event.Fields, "fd.l4proto"), "unknown"),
			SourceIP:   srcIP,
			SourcePort: intField(event.Fields, "fd.sport"),
			DestIP:     dstIP,
			DestPort:   intField(event.Fields, "fd.dport"),
			BytesSent:  int64Field(event.Fields, "evt.sent"),
			BytesRecv:  int64Field(event.Fields, "evt.recv"),
		})
	}
}

func syscallNameOrDefault(fields map[string]interface{}) string {
	if syscallName := stringField(fields, "evt.type"); syscallName != "" {
		return syscallName
	}
	return "file-access"
}

func inferFileOperation(rule string, syscall string) string {
	value := strings.ToLower(rule + " " + syscall)
	switch {
	case strings.Contains(value, "open") || strings.Contains(value, "read"):
		return "read"
	case strings.Contains(value, "write") || strings.Contains(value, "modify") || strings.Contains(value, "creat"):
		return "write"
	case strings.Contains(value, "delete") || strings.Contains(value, "unlink"):
		return "delete"
	default:
		return "access"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func stringField(fields map[string]interface{}, key string) string {
	if fields == nil {
		return ""
	}
	raw, ok := fields[key]
	if !ok || raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(toString(raw)), "\n", " "))
	}
}

func intField(fields map[string]interface{}, key string) int {
	if fields == nil {
		return 0
	}
	raw, ok := fields[key]
	if !ok || raw == nil {
		return 0
	}
	switch value := raw.(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	case float32:
		return int(value)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func int64Field(fields map[string]interface{}, key string) int64 {
	if fields == nil {
		return 0
	}
	raw, ok := fields[key]
	if !ok || raw == nil {
		return 0
	}
	switch value := raw.(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	case float32:
		return int64(value)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func toString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}

func mapPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "emergency", "alert", "critical":
		return "critical"
	case "error", "warning":
		return "high"
	case "notice":
		return "medium"
	default:
		return "medium"
	}
}
