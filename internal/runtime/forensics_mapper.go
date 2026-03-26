package runtime

import (
	"kubesentinel/internal/forensics"
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

	return forensics.ForensicRecord{
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
