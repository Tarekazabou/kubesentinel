package forensics

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Vault manages forensic evidence storage
type Vault struct {
	Config  *VaultConfig
	Storage *StorageBackend
	Policy  *RetentionPolicy
	mu      sync.RWMutex
}

// VaultConfig holds vault configuration
type VaultConfig struct {
	StoragePath   string
	RetentionDays int
	MaxSizeMB     int
	Compression   bool
}

// ForensicRecord represents a stored forensic event
type ForensicRecord struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	IncidentType  string                 `json:"incident_type"`
	Severity      string                 `json:"severity"`
	RiskScore     float64                `json:"risk_score"`
	Container     ContainerContext       `json:"container"`
	Events        []SecurityEvent        `json:"events"`
	SystemCalls   []SystemCall           `json:"system_calls"`
	NetworkTraces []NetworkTrace         `json:"network_traces"`
	FileOperations []FileOperation       `json:"file_operations"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ContainerContext holds container information
type ContainerContext struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
	Labels    map[string]string `json:"labels"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Rule      string                 `json:"rule"`
	Priority  string                 `json:"priority"`
	Output    string                 `json:"output"`
	Fields    map[string]interface{} `json:"fields"`
}

// SystemCall represents a captured system call
type SystemCall struct {
	Timestamp time.Time `json:"timestamp"`
	Name      string    `json:"name"`
	Process   string    `json:"process"`
	PID       int       `json:"pid"`
	Args      []string  `json:"args"`
	ReturnVal int       `json:"return_val"`
}

// NetworkTrace represents network activity
type NetworkTrace struct {
	Timestamp   time.Time `json:"timestamp"`
	Protocol    string    `json:"protocol"`
	SourceIP    string    `json:"source_ip"`
	SourcePort  int       `json:"source_port"`
	DestIP      string    `json:"dest_ip"`
	DestPort    int       `json:"dest_port"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`
}

// FileOperation represents file system activity
type FileOperation struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	FilePath  string    `json:"file_path"`
	Process   string    `json:"process"`
	PID       int       `json:"pid"`
	Success   bool      `json:"success"`
}

// NewVault creates a new forensic vault
func NewVault(config *VaultConfig) (*Vault, error) {
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	storage := NewStorageBackend(config.StoragePath)
	policy := NewRetentionPolicy(config.RetentionDays, config.MaxSizeMB)

	return &Vault{
		Config:  config,
		Storage: storage,
		Policy:  policy,
	}, nil
}

// StoreRecord stores a forensic record
func (v *Vault) StoreRecord(record ForensicRecord) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Generate ID if not set
	if record.ID == "" {
		record.ID = generateID()
	}

	// Set timestamp if not set
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}

	// Check retention policy
	if !v.Policy.ShouldRetain(record) {
		return fmt.Errorf("record does not meet retention criteria")
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	// Store the record
	filename := fmt.Sprintf("%s_%s.json", 
		record.Timestamp.Format("20060102_150405"),
		record.ID)
	
	path := filepath.Join(v.Config.StoragePath, filename)
	
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write record: %w", err)
	}

	fmt.Printf("Stored forensic record: %s (severity: %s, risk: %.2f)\n",
		record.ID, record.Severity, record.RiskScore)

	return nil
}

// GetRecord retrieves a forensic record by ID
func (v *Vault) GetRecord(id string) (*ForensicRecord, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Find file with matching ID
	files, err := filepath.Glob(filepath.Join(v.Config.StoragePath, "*_"+id+".json"))
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("record not found: %s", id)
	}

	// Read the file
	data, err := ioutil.ReadFile(files[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read record: %w", err)
	}

	// Unmarshal
	var record ForensicRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal record: %w", err)
	}

	return &record, nil
}

// ListRecords lists all forensic records within a time range
func (v *Vault) ListRecords(from, to time.Time) ([]ForensicRecord, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	records := []ForensicRecord{}

	files, err := filepath.Glob(filepath.Join(v.Config.StoragePath, "*.json"))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}

		var record ForensicRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		// Filter by time range
		if record.Timestamp.After(from) && record.Timestamp.Before(to) {
			records = append(records, record)
		}
	}

	return records, nil
}

// CleanupOldRecords removes records older than retention period
func (v *Vault) CleanupOldRecords() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -v.Config.RetentionDays)

	files, err := filepath.Glob(filepath.Join(v.Config.StoragePath, "*.json"))
	if err != nil {
		return err
	}

	deleted := 0
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(file); err != nil {
				fmt.Printf("Warning: failed to delete old record %s: %v\n", file, err)
				continue
			}
			deleted++
		}
	}

	if deleted > 0 {
		fmt.Printf("Cleaned up %d old forensic records\n", deleted)
	}

	return nil
}

// StorageBackend handles low-level storage operations
type StorageBackend struct {
	BasePath string
}

// NewStorageBackend creates a new storage backend
func NewStorageBackend(basePath string) *StorageBackend {
	return &StorageBackend{
		BasePath: basePath,
	}
}

// RetentionPolicy determines what should be retained
type RetentionPolicy struct {
	RetentionDays int
	MaxSizeMB     int
}

// NewRetentionPolicy creates a new retention policy
func NewRetentionPolicy(days, maxSizeMB int) *RetentionPolicy {
	return &RetentionPolicy{
		RetentionDays: days,
		MaxSizeMB:     maxSizeMB,
	}
}

// ShouldRetain determines if a record should be retained
func (rp *RetentionPolicy) ShouldRetain(record ForensicRecord) bool {
	// Always retain high severity
	if record.Severity == "critical" || record.Severity == "high" {
		return true
	}

	// Retain medium severity if risk score is high
	if record.Severity == "medium" && record.RiskScore > 0.7 {
		return true
	}

	// Retain if confirmed incident
	if record.IncidentType != "" && record.IncidentType != "false-positive" {
		return true
	}

	return false
}

// Helper functions

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
