package forensics

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreRecord_CompressionEnabled_WritesGzipAndReadsBack(t *testing.T) {
	tmp := t.TempDir()

	vault, err := NewVault(&VaultConfig{
		StoragePath:   tmp,
		RetentionDays: 30,
		MaxSizeMB:     50,
		Compression:   true,
	})
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	record := ForensicRecord{
		Timestamp:    time.Now().UTC(),
		IncidentType: "suspicious-process",
		Severity:     "high",
		RiskScore:    0.91,
	}

	if err := vault.StoreRecord(record); err != nil {
		t.Fatalf("StoreRecord failed: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(tmp, "*.json.gz"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 compressed file, got %d", len(files))
	}

	stored, err := readRecordFromPath(files[0])
	if err != nil {
		t.Fatalf("readRecordFromPath failed: %v", err)
	}

	if stored.Severity != "high" {
		t.Fatalf("expected severity high, got %q", stored.Severity)
	}
}

func TestStoreRecord_MaxSizePrunesOldestLowValueFirst(t *testing.T) {
	tmp := t.TempDir()

	vault, err := NewVault(&VaultConfig{
		StoragePath:   tmp,
		RetentionDays: 30,
		MaxSizeMB:     1,
		Compression:   false,
	})
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	payload := strings.Repeat("X", 350*1024)
	baseTime := time.Now().Add(-10 * time.Minute)

	oldLow := ForensicRecord{
		Timestamp:    baseTime,
		IncidentType: "generic-alert",
		Severity:     "low",
		RiskScore:    0.5,
		Metadata: map[string]interface{}{
			"payload": payload,
		},
	}
	highCritical := ForensicRecord{
		Timestamp:    baseTime.Add(1 * time.Minute),
		IncidentType: "critical-incident",
		Severity:     "critical",
		RiskScore:    0.99,
		Metadata: map[string]interface{}{
			"payload": payload,
		},
	}
	newLow := ForensicRecord{
		Timestamp:    baseTime.Add(2 * time.Minute),
		IncidentType: "generic-alert-2",
		Severity:     "low",
		RiskScore:    0.51,
		Metadata: map[string]interface{}{
			"payload": payload,
		},
	}

	if err := vault.StoreRecord(oldLow); err != nil {
		t.Fatalf("StoreRecord(oldLow) failed: %v", err)
	}
	if err := vault.StoreRecord(highCritical); err != nil {
		t.Fatalf("StoreRecord(highCritical) failed: %v", err)
	}
	if err := vault.StoreRecord(newLow); err != nil {
		t.Fatalf("StoreRecord(newLow) failed: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(tmp, "*.json"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatalf("expected records to remain after pruning")
	}

	hasCritical := false
	hasOldLow := false
	for _, file := range files {
		rec, err := readRecordFromPath(file)
		if err != nil {
			t.Fatalf("failed reading %s: %v", file, err)
		}
		if rec.Severity == "critical" {
			hasCritical = true
		}
		if rec.Severity == "low" && rec.IncidentType == "generic-alert" {
			hasOldLow = true
		}
	}

	if !hasCritical {
		t.Fatalf("expected critical record to be preserved")
	}
	if hasOldLow {
		t.Fatalf("expected oldest low-value record to be pruned first")
	}
}
