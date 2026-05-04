package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Generator generates forensic investigation reports
type Generator struct {
	Config *ReportConfig
}

// ReportConfig holds report generation configuration
type ReportConfig struct {
	OutputPath string
	Formats    []string
}

// Report represents a forensic investigation report
type Report struct {
	ID                 string
	Title              string
	GeneratedAt        time.Time
	TimeRange          TimeRange
	Summary            Summary
	Incidents          []Incident
	Timeline           []TimelineEvent
	Recommendations    []Recommendation
	Narrative          string
	LLMFindings        []string
	LLMRecommendations []Recommendation
	Statistics         Statistics
}

// TimeRange represents a time period
type TimeRange struct {
	From time.Time
	To   time.Time
}

// Summary contains executive summary information
type Summary struct {
	TotalIncidents     int
	CriticalIncidents  int
	HighIncidents      int
	MediumIncidents    int
	LowIncidents       int
	AffectedContainers int
	TopThreats         []string
	OverallRisk        string
}

// Incident represents a security incident
type Incident struct {
	ID          string
	Timestamp   time.Time
	Severity    string
	Type        string
	Description string
	Container   string
	RiskScore   float64
	Evidence    []string
	Status      string
}

// TimelineEvent represents an event in the timeline
type TimelineEvent struct {
	Timestamp   time.Time
	Type        string
	Severity    string
	Description string
	Container   string
}

// Recommendation represents a security recommendation
type Recommendation struct {
	Priority    string
	Title       string
	Description string
	Impact      string
	Effort      string
}

// Statistics contains report statistics
type Statistics struct {
	TotalEvents         int
	EventsByType        map[string]int
	EventsBySeverity    map[string]int
	EventsByContainer   map[string]int
	AverageRiskScore    float64
	DetectionEfficiency float64
}

// NewGenerator creates a new report generator
func NewGenerator(config *ReportConfig) *Generator {
	return &Generator{
		Config: config,
	}
}

// Generate generates reports in all configured formats
func (g *Generator) Generate(report Report) error {
	if err := os.MkdirAll(g.Config.OutputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output path: %w", err)
	}

	for _, format := range g.Config.Formats {
		switch format {
		case "markdown":
			if err := g.generateMarkdown(report); err != nil {
				return fmt.Errorf("failed to generate markdown report: %w", err)
			}
		case "json":
			if err := g.generateJSON(report); err != nil {
				return fmt.Errorf("failed to generate JSON report: %w", err)
			}
		case "html":
			if err := g.generateHTML(report); err != nil {
				return fmt.Errorf("failed to generate HTML report: %w", err)
			}
		default:
			return fmt.Errorf("unsupported format: %s", format)
		}
	}

	return nil
}

// generateMarkdown generates a markdown report
func (g *Generator) generateMarkdown(report Report) error {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# %s\n\n", report.Title))
	sb.WriteString(fmt.Sprintf("**Report ID:** %s\n\n", report.ID))
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Time Range:** %s to %s\n\n",
		report.TimeRange.From.Format("2006-01-02 15:04:05"),
		report.TimeRange.To.Format("2006-01-02 15:04:05")))

	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("**Overall Risk Level:** %s\n\n", report.Summary.OverallRisk))
	sb.WriteString(fmt.Sprintf("**Total Incidents:** %d\n", report.Summary.TotalIncidents))
	sb.WriteString(fmt.Sprintf("- Critical: %d\n", report.Summary.CriticalIncidents))
	sb.WriteString(fmt.Sprintf("- High: %d\n", report.Summary.HighIncidents))
	sb.WriteString(fmt.Sprintf("- Medium: %d\n", report.Summary.MediumIncidents))
	sb.WriteString(fmt.Sprintf("- Low: %d\n\n", report.Summary.LowIncidents))

	sb.WriteString(fmt.Sprintf("**Affected Containers:** %d\n\n", report.Summary.AffectedContainers))

	if len(report.Summary.TopThreats) > 0 {
		sb.WriteString("**Top Threats:**\n")
		for i, threat := range report.Summary.TopThreats {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, threat))
		}
		sb.WriteString("\n")
	}

	// Incidents
	if len(report.Incidents) > 0 {
		sb.WriteString("## Incidents\n\n")

		// Sort by severity
		incidents := report.Incidents
		sort.Slice(incidents, func(i, j int) bool {
			return getSeverityWeight(incidents[i].Severity) > getSeverityWeight(incidents[j].Severity)
		})

		for _, incident := range incidents {
			sb.WriteString(fmt.Sprintf("### %s - %s\n\n", incident.ID, incident.Type))
			sb.WriteString(fmt.Sprintf("**Severity:** %s | **Risk Score:** %.2f\n\n",
				incident.Severity, incident.RiskScore))
			sb.WriteString(fmt.Sprintf("**Time:** %s\n\n",
				incident.Timestamp.Format("2006-01-02 15:04:05")))
			sb.WriteString(fmt.Sprintf("**Container:** %s\n\n", incident.Container))
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", incident.Description))

			if len(incident.Evidence) > 0 {
				sb.WriteString("**Evidence:**\n")
				for _, evidence := range incident.Evidence {
					sb.WriteString(fmt.Sprintf("- %s\n", evidence))
				}
				sb.WriteString("\n")
			}

			sb.WriteString(fmt.Sprintf("**Status:** %s\n\n", incident.Status))
			sb.WriteString("---\n\n")
		}
	}

	// Timeline
	if len(report.Timeline) > 0 {
		sb.WriteString("## Timeline\n\n")

		for _, event := range report.Timeline {
			severity := strings.ToUpper(event.Severity)
			sb.WriteString(fmt.Sprintf("- **%s** [%s] %s: %s\n",
				event.Timestamp.Format("15:04:05"),
				severity,
				event.Type,
				event.Description))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		sb.WriteString("## Recommendations\n\n")

		for i, rec := range report.Recommendations {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, rec.Title))
			sb.WriteString(fmt.Sprintf("**Priority:** %s | **Impact:** %s | **Effort:** %s\n\n",
				rec.Priority, rec.Impact, rec.Effort))
			sb.WriteString(fmt.Sprintf("%s\n\n", rec.Description))
		}
	}

	// Statistics
	sb.WriteString("## Statistics\n\n")
	sb.WriteString(fmt.Sprintf("**Total Events Processed:** %d\n\n", report.Statistics.TotalEvents))

	if len(report.Statistics.EventsByType) > 0 {
		sb.WriteString("**Events by Type:**\n")
		for eventType, count := range report.Statistics.EventsByType {
			sb.WriteString(fmt.Sprintf("- %s: %d\n", eventType, count))
		}
		sb.WriteString("\n")
	}

	if len(report.Statistics.EventsBySeverity) > 0 {
		sb.WriteString("**Events by Severity:**\n")
		for severity, count := range report.Statistics.EventsBySeverity {
			sb.WriteString(fmt.Sprintf("- %s: %d\n", severity, count))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("**Average Risk Score:** %.2f\n", report.Statistics.AverageRiskScore))
	sb.WriteString(fmt.Sprintf("**Detection Efficiency:** %.1f%%\n\n",
		report.Statistics.DetectionEfficiency*100))

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString("*This report was generated by KubeSentinel*\n")

	// Write to file
	filename := fmt.Sprintf("report_%s_%s.md",
		report.ID,
		report.GeneratedAt.Format("20060102_150405"))

	path := filepath.Join(g.Config.OutputPath, filename)

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write markdown report: %w", err)
	}

	fmt.Printf("Generated markdown report: %s\n", path)
	return nil
}

// generateJSON generates a JSON report (simplified for brevity)
func (g *Generator) generateJSON(report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report JSON: %w", err)
	}

	filename := fmt.Sprintf("report_%s_%s.json",
		report.ID,
		report.GeneratedAt.Format("20060102_150405"))
	path := filepath.Join(g.Config.OutputPath, filename)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write json report: %w", err)
	}

	fmt.Printf("Generated JSON report: %s\n", path)
	return nil
}

// generateHTML generates an HTML report (simplified for brevity)
func (g *Generator) generateHTML(report Report) error {
	const reportTemplate = `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8" />
	<title>{{.Title}}</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }
		h1, h2, h3 { margin-bottom: 8px; }
		.muted { color: #6b7280; }
		.card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
		table { border-collapse: collapse; width: 100%; }
		th, td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }
		th { background: #f9fafb; }
	</style>
</head>
<body>
	<h1>{{.Title}}</h1>
	<p class="muted">Report ID: {{.ID}} | Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</p>
	<p class="muted">Range: {{.TimeRange.From.Format "2006-01-02 15:04:05"}} → {{.TimeRange.To.Format "2006-01-02 15:04:05"}}</p>

	<h2>Summary</h2>
	<div class="card">
		<p><strong>Overall Risk:</strong> {{.Summary.OverallRisk}}</p>
		<p><strong>Total Incidents:</strong> {{.Summary.TotalIncidents}}</p>
		<p>Critical: {{.Summary.CriticalIncidents}} | High: {{.Summary.HighIncidents}} | Medium: {{.Summary.MediumIncidents}} | Low: {{.Summary.LowIncidents}}</p>
		<p><strong>Affected Containers:</strong> {{.Summary.AffectedContainers}}</p>
	</div>

	{{if .Narrative}}<h2>Narrative</h2><div class="card">{{.Narrative}}</div>{{end}}

	<h2>Incidents</h2>
	{{range .Incidents}}
		<div class="card">
			<h3>{{.ID}} - {{.Type}}</h3>
			<p><strong>Severity:</strong> {{.Severity}} | <strong>Risk:</strong> {{printf "%.2f" .RiskScore}} | <strong>Status:</strong> {{.Status}}</p>
			<p><strong>Container:</strong> {{.Container}}</p>
			<p>{{.Description}}</p>
		</div>
	{{else}}
		<p>No incidents found in selected range.</p>
	{{end}}

	<h2>Timeline</h2>
	<table>
		<thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Description</th><th>Container</th></tr></thead>
		<tbody>
			{{range .Timeline}}
			<tr>
				<td>{{.Timestamp.Format "2006-01-02 15:04:05"}}</td>
				<td>{{.Severity}}</td>
				<td>{{.Type}}</td>
				<td>{{.Description}}</td>
				<td>{{.Container}}</td>
			</tr>
			{{end}}
		</tbody>
	</table>

	<h2>Recommendations</h2>
	<ul>
		{{range .Recommendations}}<li><strong>{{.Priority}}:</strong> {{.Title}} — {{.Description}}</li>{{end}}
		{{range .LLMRecommendations}}<li><strong>{{.Priority}} (LLM):</strong> {{.Title}} — {{.Description}}</li>{{end}}
	</ul>
</body>
</html>`

	tmpl, err := template.New("forensic_report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse html template: %w", err)
	}

	filename := fmt.Sprintf("report_%s_%s.html",
		report.ID,
		report.GeneratedAt.Format("20060102_150405"))
	path := filepath.Join(g.Config.OutputPath, filename)

	htmlFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create html report: %w", err)
	}
	defer htmlFile.Close()

	if err := tmpl.Execute(htmlFile, report); err != nil {
		return fmt.Errorf("failed to render html report: %w", err)
	}

	fmt.Printf("Generated HTML report: %s\n", path)
	return nil
}

// Helper function
func getSeverityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
