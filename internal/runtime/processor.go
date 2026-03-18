package runtime

import (
	"context"
	"fmt"
	"kubesentinel/internal/ai"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EventProcessor handles concurrent processing of security events
type EventProcessor struct {
	Workers          int
	FeatureExtractor *FeatureExtractor
	Metrics          *ProcessorMetrics
	AIClient         *ai.Client
	wg               sync.WaitGroup
}

// ProcessorMetrics tracks processing statistics
type ProcessorMetrics struct {
	TotalEvents       int64
	ProcessedEvents   int64
	AnomaliesDetected int64
	ErrorCount        int64
	AICalls           int64 // New field for tracking AI API calls
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
	ProcessName      string         `json:"process_name"`
	ProcessFrequency int            `json:"process_frequency"`
	SyscallCount     map[string]int `json:"syscall_count"`
	FileAccessCount  int            `json:"file_access_count"`
	NetworkConnCount int            `json:"network_conn_count"`
	SensitiveFiles   []string       `json:"sensitive_files"`
	CommandLine      string         `json:"command_line"`
	ParentProcess    string         `json:"parent_process"`
	UserID           string         `json:"user_id"`
	TimeWindow       string         `json:"time_window"`
	ContainerID      string         `json:"container_id"`
	Namespace        string         `json:"namespace"`
	TimeOfDay        int            `json:"time_of_day"`
	DayOfWeek        int            `json:"day_of_week"`
	ContainerAge     int            `json:"container_age"`
}

// NewEventProcessor creates a new event processor
// TrainBaseline collects normal events (score < 0.3) and retrains the model every 50 samples
func (ep *EventProcessor) TrainBaseline(ctx context.Context) {
	// You can implement a small buffer + ticker, or call manually.
	// For Week 6 the minimal version is enough:
	fmt.Println("Baseline training workflow ready – call ep.AIClient.UpdateBaseline(...) with normal FeatureVector slices")
}
func NewEventProcessor(workers int, aiClient *ai.Client) *EventProcessor {
	return &EventProcessor{
		Workers:          workers,
		FeatureExtractor: NewFeatureExtractor(),
		Metrics: &ProcessorMetrics{
			TotalEvents:       0,
			ProcessedEvents:   0,
			AnomaliesDetected: 0,
			ErrorCount:        0,
			AICalls:           0,
		},
		AIClient: aiClient, // now comes from parameter
	}
}

// Start begins processing events with worker goroutines
func (ep *EventProcessor) Start(ctx context.Context, eventChan <-chan SecurityEvent) {
	ep.wg.Add(ep.Workers) // ← use struct field

	for i := 0; i < ep.Workers; i++ {
		go func(workerID int) {
			defer ep.wg.Done() // ← now on struct wg
			ep.worker(ctx, workerID, eventChan)
		}(i)
	}

	// Optional: keep the "All stopped" message in background
	go func() {
		ep.wg.Wait()
		fmt.Println("All event processors stopped")
	}()
}
func (ep *EventProcessor) Wait() {
	ep.wg.Wait()
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
			if _, err := ep.ProcessEvent(event); err != nil {
				atomic.AddInt64(&ep.Metrics.ErrorCount, 1)
				fmt.Printf("Worker %d: error processing event: %v\n", id, err)
				continue
			}

			// Increment processed counter
			atomic.AddInt64(&ep.Metrics.ProcessedEvents, 1)
		}
	}
}
func (fe *FeatureExtractor) ExtractFeatures(event SecurityEvent) BehavioralFeatures {
	features := BehavioralFeatures{
		SyscallCount: make(map[string]int),
	}
	fmt.Printf("Debug: Event Fields: %v\n", event.Fields)
	if event.Fields != nil {
		if cmdline, ok := event.Fields["proc.cmdline"].(string); ok {
			features.CommandLine = cmdline
		}
		if pname, ok := event.Fields["proc.pname"].(string); ok {
			features.ProcessName = pname
		}
		if uid, ok := event.Fields["user.uid"].(string); ok {
			features.UserID = uid
		}
		if fdName, ok := event.Fields["fd.name"].(string); ok {
			features.SensitiveFiles = append(features.SensitiveFiles, fdName)
		}
		// Add more field mappings as needed for Week 4 patterns
	}

	return features
}

func (ep *EventProcessor) toAIFeatureVector(features BehavioralFeatures, event SecurityEvent) ai.FeatureVector {
	return ai.FeatureVector{
		ProcessName:      features.ProcessName,
		ProcessFrequency: features.ProcessFrequency,
		FileAccessCount:  features.FileAccessCount,
		NetworkCount:     features.NetworkConnCount,
		SensitiveFiles:   len(features.SensitiveFiles),
		UserID:           features.UserID,
		TimeOfDay:        features.TimeOfDay,
		DayOfWeek:        features.DayOfWeek,
		ContainerAge:     features.ContainerAge,
	}
}
func (ep *EventProcessor) getAIRiskScore(features BehavioralFeatures, event SecurityEvent) float64 {
	fmt.Printf("[DEBUG-AI] Entering AI scoring for process=%s file_access=%d sensitive=%d\n",
		features.ProcessName, features.FileAccessCount, len(features.SensitiveFiles))

	if ep.AIClient == nil {
		fmt.Println("[DEBUG-AI] AIClient is nil → using fallback")
		return ep.calculateRisk(event, features)
	}

	aiVec := ep.toAIFeatureVector(features, event)

	// INCREASED TIMEOUT: 200ms is too short for a Python Flask overhead
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := ep.AIClient.DetectAnomaly(ctx, aiVec)
	if err != nil {
		fmt.Printf("[AI ERROR] %v → using fallback\n", err)
		atomic.AddInt64(&ep.Metrics.ErrorCount, 1)
		return ep.calculateRisk(event, features)
	}

	// Record success metrics
	atomic.AddInt64(&ep.Metrics.AICalls, 1)

	// This is the log you've been looking for!
	fmt.Printf("[AI PREDICTION] score=%.3f | is_anomaly=%v | process=%s | reason=%s\n",
		resp.Score, resp.IsAnomaly, features.ProcessName, resp.Reason)

	return resp.Score
}

func (ep *EventProcessor) ProcessEvent(event SecurityEvent) (ProcessedEvent, error) {
	// Note: Removed atomic.AddInt64 here because worker() already does it.

	features := ep.FeatureExtractor.Extract(event)
	fmt.Printf("[PROC] Extracted features for %s | file_access=%d | sensitive=%d\n",
		features.ProcessName, features.FileAccessCount, len(features.SensitiveFiles))

	riskScore := ep.getAIRiskScore(features, event)

	isAnomaly := riskScore >= 0.5

	if isAnomaly {
		atomic.AddInt64(&ep.Metrics.AnomaliesDetected, 1)
	}

	return ProcessedEvent{
		Original:  event,
		Features:  features,
		Timestamp: time.Now(),
		RiskScore: riskScore,
		Anomaly:   isAnomaly,
	}, nil
}

// Simple rule-based scoring engine for Week 4
func (p *EventProcessor) calculateRisk(event SecurityEvent, features BehavioralFeatures) float64 {
	score := 0.0

	// Rule 1: Explicit malicious commands
	if strings.Contains(features.CommandLine, "cat /etc/shadow") {
		score += 0.8
	}

	// Rule 2: Access to sensitive files detected by FeatureExtractor
	if len(features.SensitiveFiles) > 0 {
		score += 0.5
	}

	// Rule 3: Root user in kube-system (highly suspicious)
	if features.UserID == "0" && event.Container.Namespace == "kube-system" {
		score += 0.2
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
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
		AICalls:           atomic.LoadInt64(&ep.Metrics.AICalls), // ← ADD THIS
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
	features.TimeOfDay = event.Timestamp.Hour()
	features.DayOfWeek = int(event.Timestamp.Weekday())
	features.ContainerAge = 0 // TODO: later pull from k8s.pod.startTime via Falco field if needed

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
