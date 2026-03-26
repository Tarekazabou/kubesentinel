package reporting

import (
	"fmt"
	"kubesentinel/internal/forensics"
	"sort"
	"strings"
	"time"
)

// BuildReport deterministically assembles a report from forensic records.
func BuildReport(records []forensics.ForensicRecord, from, to time.Time) Report {
	sorted := make([]forensics.ForensicRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	if from.IsZero() || to.IsZero() {
		computedFrom, computedTo := inferRange(sorted)
		if from.IsZero() {
			from = computedFrom
		}
		if to.IsZero() {
			to = computedTo
		}
	}

	report := Report{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Title:       "KubeSentinel Forensic Investigation Report",
		GeneratedAt: time.Now().UTC(),
		TimeRange: TimeRange{
			From: from,
			To:   to,
		},
		Statistics: Statistics{
			EventsByType:      map[string]int{},
			EventsBySeverity:  map[string]int{},
			EventsByContainer: map[string]int{},
		},
	}

	containerSet := map[string]struct{}{}
	threatCounts := map[string]int{}
	incidentCounts := map[string]int{}
	severityCounts := map[string]int{}
	var totalRisk float64
	var timeline []TimelineEvent

	for index, record := range sorted {
		severity := strings.ToLower(strings.TrimSpace(record.Severity))
		if severity == "" {
			severity = "medium"
		}

		containerName := firstNonEmpty(record.Container.Name, record.Container.PodName, record.Container.ID, "unknown")
		containerSet[containerName] = struct{}{}
		threatKey := firstNonEmpty(record.IncidentType, "unknown")
		threatCounts[threatKey]++
		severityCounts[severity]++
		incidentCounts[threatKey]++

		report.Statistics.EventsBySeverity[severity]++
		report.Statistics.EventsByContainer[containerName]++
		report.Statistics.EventsByType[threatKey]++
		totalRisk += record.RiskScore

		description := summarizeRecord(record)
		report.Incidents = append(report.Incidents, Incident{
			ID:          firstNonEmpty(record.ID, fmt.Sprintf("incident-%03d", index+1)),
			Timestamp:   record.Timestamp,
			Severity:    severity,
			Type:        threatKey,
			Description: description,
			Container:   containerName,
			RiskScore:   record.RiskScore,
			Evidence:    evidenceList(record),
			Status:      "open",
		})

		if len(record.Events) == 0 {
			timeline = append(timeline, TimelineEvent{
				Timestamp:   record.Timestamp,
				Type:        threatKey,
				Severity:    severity,
				Description: description,
				Container:   containerName,
			})
			continue
		}

		for _, event := range record.Events {
			timeline = append(timeline, TimelineEvent{
				Timestamp:   event.Timestamp,
				Type:        threatKey,
				Severity:    severity,
				Description: firstNonEmpty(event.Output, description),
				Container:   containerName,
			})
		}
	}

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})
	report.Timeline = timeline

	report.Summary = Summary{
		TotalIncidents:     len(report.Incidents),
		CriticalIncidents:  severityCounts["critical"],
		HighIncidents:      severityCounts["high"],
		MediumIncidents:    severityCounts["medium"],
		LowIncidents:       severityCounts["low"],
		AffectedContainers: len(containerSet),
		TopThreats:         topThreats(threatCounts, 5),
		OverallRisk:        overallRisk(severityCounts, averageRisk(totalRisk, len(sorted))),
	}

	report.Statistics.TotalEvents = len(timeline)
	report.Statistics.AverageRiskScore = averageRisk(totalRisk, len(sorted))
	report.Statistics.DetectionEfficiency = detectionEfficiency(len(report.Incidents), len(timeline))

	report.Recommendations = recommendationsFromSummary(report.Summary, incidentCounts)
	return report
}

func inferRange(records []forensics.ForensicRecord) (time.Time, time.Time) {
	if len(records) == 0 {
		now := time.Now().UTC()
		return now.Add(-24 * time.Hour), now
	}
	from := records[0].Timestamp
	to := records[len(records)-1].Timestamp
	if from.IsZero() || to.IsZero() {
		now := time.Now().UTC()
		return now.Add(-24 * time.Hour), now
	}
	return from, to
}

func evidenceList(record forensics.ForensicRecord) []string {
	evidence := []string{}
	if len(record.SystemCalls) > 0 {
		evidence = append(evidence, fmt.Sprintf("%d syscall(s) captured", len(record.SystemCalls)))
	}
	if len(record.FileOperations) > 0 {
		evidence = append(evidence, fmt.Sprintf("%d file operation(s) captured", len(record.FileOperations)))
	}
	if len(record.NetworkTraces) > 0 {
		evidence = append(evidence, fmt.Sprintf("%d network trace(s) captured", len(record.NetworkTraces)))
	}
	if len(record.Events) > 0 {
		evidence = append(evidence, fmt.Sprintf("%d triggering event(s)", len(record.Events)))
	}
	if len(evidence) == 0 {
		evidence = append(evidence, "No additional evidence captured")
	}
	return evidence
}

func summarizeRecord(record forensics.ForensicRecord) string {
	if len(record.Events) > 0 && strings.TrimSpace(record.Events[0].Output) != "" {
		return record.Events[0].Output
	}
	return fmt.Sprintf("%s detected with risk score %.2f", firstNonEmpty(record.IncidentType, "Anomaly"), record.RiskScore)
}

func topThreats(threatCounts map[string]int, limit int) []string {
	type kv struct {
		key   string
		count int
	}
	items := make([]kv, 0, len(threatCounts))
	for key, count := range threatCounts {
		items = append(items, kv{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].key < items[j].key
		}
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.key)
	}
	return out
}

func overallRisk(severityCounts map[string]int, avgRisk float64) string {
	if severityCounts["critical"] > 0 {
		return "critical"
	}
	if severityCounts["high"] > 0 || avgRisk >= 0.75 {
		return "high"
	}
	if severityCounts["medium"] > 0 || avgRisk >= 0.4 {
		return "medium"
	}
	return "low"
}

func averageRisk(total float64, count int) float64 {
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

func detectionEfficiency(incidents int, events int) float64 {
	if events == 0 {
		return 0
	}
	value := float64(incidents) / float64(events)
	if value > 1 {
		return 1
	}
	return value
}

func recommendationsFromSummary(summary Summary, incidentCounts map[string]int) []Recommendation {
	recs := []Recommendation{}
	if summary.CriticalIncidents > 0 {
		recs = append(recs, Recommendation{
			Priority:    "critical",
			Title:       "Contain critical workloads",
			Description: "Isolate affected pods, rotate credentials, and investigate process execution history immediately.",
			Impact:      "high",
			Effort:      "medium",
		})
	}
	if summary.HighIncidents > 0 {
		recs = append(recs, Recommendation{
			Priority:    "high",
			Title:       "Harden runtime policies",
			Description: "Restrict container capabilities, enforce read-only roots, and tighten seccomp/AppArmor profiles.",
			Impact:      "high",
			Effort:      "medium",
		})
	}
	if incidentCounts["Terminal shell in container"] > 0 {
		recs = append(recs, Recommendation{
			Priority:    "high",
			Title:       "Block interactive shells in production",
			Description: "Disable shell binaries where possible and alert on shell spawns from service containers.",
			Impact:      "high",
			Effort:      "low",
		})
	}
	if len(recs) == 0 {
		recs = append(recs, Recommendation{
			Priority:    "medium",
			Title:       "Review anomaly baseline",
			Description: "No high-impact incidents found; verify baseline quality and continue monitoring.",
			Impact:      "medium",
			Effort:      "low",
		})
	}
	return recs
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
