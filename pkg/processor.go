package runtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// EventProcessor handles concurrent processing of security events
type EventProcessor struct {
	Workers          int
	FeatureExtractor *FeatureExtractor
	Metrics          *ProcessorMetrics
}

// ProcessorMetrics tracks processing statistics
type ProcessorMetrics struct {
	TotalEvents       int64
	ProcessedEvents   int64
	AnomaliesDetected int64
	ErrorCount        int64
}

// ProcessedEvent represents an event after processing
type ProcessedEvent struct {
	Original  SecurityEvent
	Features  BehavioralFeatures
	Timestamp time.Time
	RiskScore float64
	Anomaly   bool
}

// BehavioralFeatures represents extracted behavioral features
type BehavioralFeatures struct {
	ProcessName       string            `json:"process_name"`
	ProcessFrequency  int               `json:"process_frequency"`
	SyscallCount      map[string]int    `json:"syscall_count"`
	FileAccessCount   int               `json:"file_access_count"`
	NetworkConnCount  int               `json:"network_conn_count"`
	SensitiveFiles    []string          `json:"sensitive_files"`
	CommandLine       string            `json:"command_line"`
	ParentProcess     string            `json:"parent_process"`
	UserID            string            `json:"user_id"`
	TimeWindow        string            `json:"time_window"`
	ContainerID       string            `json:"container_id"`
	Namespace         string            `json:"namespace"`
}

// NewEventProcessor creates a new event processor
func NewEventProcessor(workers int) *EventProcessor {
	return &EventProcessor{
		Workers:          workers,
		FeatureExtractor: NewFeatureExtractor(),
		Metrics: &ProcessorMetrics{
			TotalEvents:       0,
			ProcessedEvents:   0,
			AnomaliesDetected: 0,
			ErrorCount:        0,
		},
	}
}

// Start begins processing events with worker goroutines
func (ep *EventProcessor) Start(ctx context.Context, eventChan <-chan SecurityEvent) {
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < ep.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ep.worker(ctx, workerID, eventChan)
		}(i)
	}

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		fmt.Println("All event processors stopped")
	}()
}

// worker processes events from the channel
func (ep *EventProcessor) worker(ctx context.Context, id int, eventChan <-chan SecurityEvent) {
	fmt.Printf("Worker %d started\n", id)

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("Worker %d stopping\n", id)
			return
		case event, ok := <-eventChan:
			if !ok {
				fmt.Printf("Worker %d: channel closed\n", id)
				return
			}

			// Increment total events counter
			atomic.AddInt64(&ep.Metrics.TotalEvents, 1)

			// Process the event
			if err := ep.processEvent(event); err != nil {
				atomic.AddInt64(&ep.Metrics.ErrorCount, 1)
				fmt.Printf("Worker %d: error processing event: %v\n", id, err)
				continue
			}

			// Increment processed counter
			atomic.AddInt64(&ep.Metrics.ProcessedEvents, 1)
		}
	}
}

// processEvent handles a single security event
func (ep *EventProcessor) processEvent(event SecurityEvent) error {
	// Extract behavioral features
	features := ep.FeatureExtractor.Extract(event)

	// Create processed event
	processed := ProcessedEvent{
		Original:  event,
		Features:  features,
		Timestamp: time.Now(),
		RiskScore: 0.0,
		Anomaly:   false,
	}

	// Apply rule-based detection
	if ep.isKnownThreat(event) {
		processed.RiskScore = 0.95
		processed.Anomaly = true
		atomic.AddInt64(&ep.Metrics.AnomaliesDetected, 1)
	}

	// Send to AI module for anomaly detection
	// This would integrate with the Python AI service via gRPC
	// For now, we'll use a placeholder
	aiScore := ep.getAIRiskScore(features)
	if aiScore > processed.RiskScore {
		processed.RiskScore = aiScore
	}

	if aiScore > 0.75 {
		processed.Anomaly = true
		atomic.AddInt64(&ep.Metrics.AnomaliesDetected, 1)
	}

	// Store in forensic vault if anomaly detected
	if processed.Anomaly {
		if err := ep.storeForensicData(processed); err != nil {
			return fmt.Errorf("failed to store forensic data: %w", err)
		}
	}

	return nil
}

// isKnownThreat checks for known threat patterns
func (ep *EventProcessor) isKnownThreat(event SecurityEvent) bool {
	// Check for critical priority events
	if event.Priority == "Critical" || event.Priority == "Emergency" {
		return true
	}

	// Check for specific threat patterns
	knownThreats := []string{
		"Terminal shell in container",
		"Modify binary dirs",
		"Write below etc",
		"Sensitive file opened for reading",
		"Netcat Remote Code Execution",
		"Launch Suspicious Network Tool",
	}

	for _, threat := range knownThreats {
		if event.Rule == threat {
			return true
		}
	}

	return false
}

// getAIRiskScore would call the AI service to get anomaly score
func (ep *EventProcessor) getAIRiskScore(features BehavioralFeatures) float64 {
	// Placeholder - would integrate with Python AI service via gRPC
	// For now, return a simple heuristic score
	
	score := 0.0

	// Increase score for sensitive file access
	if len(features.SensitiveFiles) > 0 {
		score += 0.3
	}

	// Increase score for high network activity
	if features.NetworkConnCount > 10 {
		score += 0.2
	}

	// Increase score for many file accesses
	if features.FileAccessCount > 50 {
		score += 0.2
	}

	// Increase score for unusual processes
	suspiciousProcesses := []string{"nc", "ncat", "netcat", "wget", "curl"}
	for _, proc := range suspiciousProcesses {
		if features.ProcessName == proc {
			score += 0.4
			break
		}
	}

	return score
}

// storeForensicData stores forensic information for anomalous events
func (ep *EventProcessor) storeForensicData(event ProcessedEvent) error {
	// This would integrate with the forensic vault
	// For now, just log
	fmt.Printf("ANOMALY DETECTED: Risk=%.2f, Rule=%s, Container=%s\n",
		event.RiskScore,
		event.Original.Rule,
		event.Original.Container.Name)
	
	return nil
}

// GetMetrics returns current processor metrics
func (ep *EventProcessor) GetMetrics() ProcessorMetrics {
	return ProcessorMetrics{
		TotalEvents:       atomic.LoadInt64(&ep.Metrics.TotalEvents),
		ProcessedEvents:   atomic.LoadInt64(&ep.Metrics.ProcessedEvents),
		AnomaliesDetected: atomic.LoadInt64(&ep.Metrics.AnomaliesDetected),
		ErrorCount:        atomic.LoadInt64(&ep.Metrics.ErrorCount),
	}
}

// FeatureExtractor extracts behavioral features from events
type FeatureExtractor struct {
	// State tracking for frequency analysis
	processFrequency map[string]int
	mu               sync.RWMutex
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		processFrequency: make(map[string]int),
	}
}

// Extract extracts behavioral features from a security event
func (fe *FeatureExtractor) Extract(event SecurityEvent) BehavioralFeatures {
	features := BehavioralFeatures{
		SyscallCount:   make(map[string]int),
		SensitiveFiles: []string{},
		TimeWindow:     getTimeWindow(event.Timestamp),
		ContainerID:    event.Container.ID,
		Namespace:      event.Container.Namespace,
	}

	// Extract from output fields
	if event.Fields != nil {
		if proc, ok := event.Fields["proc.name"].(string); ok {
			features.ProcessName = proc
			fe.updateProcessFrequency(proc)
			features.ProcessFrequency = fe.getProcessFrequency(proc)
		}

		if cmdline, ok := event.Fields["proc.cmdline"].(string); ok {
			features.CommandLine = cmdline
		}

		if parent, ok := event.Fields["proc.pname"].(string); ok {
			features.ParentProcess = parent
		}

		if uid, ok := event.Fields["user.uid"].(string); ok {
			features.UserID = uid
		}

		// Check for file operations
		if fd_name, ok := event.Fields["fd.name"].(string); ok {
			features.FileAccessCount++
			if isSensitiveFile(fd_name) {
				features.SensitiveFiles = append(features.SensitiveFiles, fd_name)
			}
		}

		// Check for network operations
		if _, ok := event.Fields["fd.sip"].(string); ok {
			features.NetworkConnCount++
		}
	}

	return features
}

// Helper methods

func (fe *FeatureExtractor) updateProcessFrequency(proc string) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.processFrequency[proc]++
}

func (fe *FeatureExtractor) getProcessFrequency(proc string) int {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.processFrequency[proc]
}

func getTimeWindow(t time.Time) string {
	// Return hour-based time window for temporal analysis
	return t.Format("2006-01-02-15")
}

func isSensitiveFile(path string) bool {
	sensitivePatterns := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/ssh",
		"/root/.ssh",
		".kube/config",
		"token",
		"secret",
		"credential",
		".aws/credentials",
	}

	for _, pattern := range sensitivePatterns {
		if contains(path, pattern) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > 0 && len(substr) > 0 && 
		(s[0:min(len(s), len(substr))] == substr[0:min(len(s), len(substr))] || 
		contains(s[1:], substr))))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
