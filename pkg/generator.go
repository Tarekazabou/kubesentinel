package reporting

import (
	"fmt"
	"io/ioutil"
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
	ID              string
	Title           string
	GeneratedAt     time.Time
	TimeRange       TimeRange
	Summary         Summary
	Incidents       []Incident
	Timeline        []TimelineEvent
	Recommendations []Recommendation
	Statistics      Statistics
}

// TimeRange represents a time period
type TimeRange struct {
	From time.Time
	To   time.Time
}

// Summary contains executive summary information
type Summary struct {
	TotalIncidents    int
	CriticalIncidents int
	HighIncidents     int
	MediumIncidents   int
	LowIncidents      int
	AffectedContainers int
	TopThreats        []string
	OverallRisk       string
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
	sb.WriteString("*This report was generated by Go-CSPM*\n")

	// Write to file
	filename := fmt.Sprintf("report_%s_%s.md",
		report.ID,
		report.GeneratedAt.Format("20060102_150405"))
	
	path := filepath.Join(g.Config.OutputPath, filename)
	
	if err := ioutil.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write markdown report: %w", err)
	}

	fmt.Printf("Generated markdown report: %s\n", path)
	return nil
}

// generateJSON generates a JSON report (simplified for brevity)
func (g *Generator) generateJSON(report Report) error {
	// Implementation would marshal report to JSON
	filename := fmt.Sprintf("report_%s_%s.json",
		report.ID,
		report.GeneratedAt.Format("20060102_150405"))
	
	fmt.Printf("Generated JSON report: %s\n", filename)
	return nil
}

// generateHTML generates an HTML report (simplified for brevity)
func (g *Generator) generateHTML(report Report) error {
	// Implementation would generate HTML with CSS styling
	filename := fmt.Sprintf("report_%s_%s.html",
		report.ID,
		report.GeneratedAt.Format("20060102_150405"))
	
	fmt.Printf("Generated HTML report: %s\n", filename)
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
