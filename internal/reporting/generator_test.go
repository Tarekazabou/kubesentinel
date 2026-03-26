package reporting

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGenerator_WritesJSONAndHTML(t *testing.T) {
	tmp := t.TempDir()
	generator := NewGenerator(&ReportConfig{
		OutputPath: tmp,
		Formats:    []string{"json", "html"},
	})

	report := Report{
		ID:          "unit",
		Title:       "Unit Report",
		GeneratedAt: time.Now().UTC(),
		TimeRange: TimeRange{
			From: time.Now().UTC().Add(-time.Hour),
			To:   time.Now().UTC(),
		},
		Summary: Summary{OverallRisk: "medium"},
	}

	if err := generator.Generate(report); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	jsonFiles, err := filepath.Glob(filepath.Join(tmp, "*.json"))
	if err != nil {
		t.Fatalf("json glob failed: %v", err)
	}
	if len(jsonFiles) != 1 {
		t.Fatalf("expected 1 json file, got %d", len(jsonFiles))
	}

	htmlFiles, err := filepath.Glob(filepath.Join(tmp, "*.html"))
	if err != nil {
		t.Fatalf("html glob failed: %v", err)
	}
	if len(htmlFiles) != 1 {
		t.Fatalf("expected 1 html file, got %d", len(htmlFiles))
	}
}
