package runtime

import (
	"context"
	"fmt"
	"kubesentinel/internal/ai"
	"kubesentinel/internal/forensics"
	"kubesentinel/internal/llm"
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
	Vault            *forensics.Vault
	GeminiClient     *llm.GeminiClient
	normalBuffer     []ai.FeatureVector
	bufferMu         sync.Mutex
	wg               sync.WaitGroup
	warmupMinutes    int
	warmupComplete   atomic.Bool
	cancelLoops      context.CancelFunc
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
	PodName          string         `json:"pod_name"`
	TimeOfDay        int            `json:"time_of_day"`
	DayOfWeek        int            `json:"day_of_week"`
	ContainerAge     int            `json:"container_age"`
}

// NewEventProcessor creates a new event processor
// TrainBaseline collects normal events (score < 0.3) and retrains the model every 50 samples
// TrainBaseline collects normal events (score < 0.3) and retrains the model
func (ep *EventProcessor) TrainBaseline(ctx context.Context) {
	ep.bufferMu.Lock()
	if len(ep.normalBuffer) < 50 {
		ep.bufferMu.Unlock()
		fmt.Printf("[BASELINE] Only %d normal events collected — waiting for more...\n", len(ep.normalBuffer))
		return
	}

	toTrain := make([]ai.FeatureVector, len(ep.normalBuffer))
	copy(toTrain, ep.normalBuffer)
	ep.normalBuffer = ep.normalBuffer[:0] // clear for next cycle
	ep.bufferMu.Unlock()

	fmt.Printf("[BASELINE] Training model with %d normal events...\n", len(toTrain))
	if err := ep.AIClient.UpdateBaseline(ctx, toTrain); err != nil {
		fmt.Printf("[BASELINE ERROR] %v\n", err)
	} else {
		fmt.Println("[BASELINE] ✅ Model successfully retrained!")
	}
}

// NewEventProcessor creates a new event processor with optional warm-up phase.
func NewEventProcessor(workers int, aiClient *ai.Client, warmupMinutes int, vault ...*forensics.Vault) *EventProcessor {
	var forensicVault *forensics.Vault
	if len(vault) > 0 {
		forensicVault = vault[0]
	}
	if warmupMinutes < 0 {
		warmupMinutes = 0
	}

	ep := &EventProcessor{
		Workers:          workers,
		FeatureExtractor: NewFeatureExtractor(),
		Metrics: &ProcessorMetrics{
			TotalEvents:       0,
			ProcessedEvents:   0,
			AnomaliesDetected: 0,
			ErrorCount:        0,
			AICalls:           0,
		},
		AIClient:       aiClient,
		Vault:          forensicVault,
		normalBuffer:   make([]ai.FeatureVector, 0, 200),
		warmupMinutes:  warmupMinutes,
		warmupComplete: atomic.Bool{}, // starts false
	}

	// === WARM-UP PHASE (one-shot) ===
	if ep.warmupMinutes > 0 {
		ep.wg.Add(1)
		go func() {
			defer ep.wg.Done()
			fmt.Printf("[WARMUP] Starting %d-minute baseline collection phase...\n", ep.warmupMinutes)

			// One-shot timer for warm-up duration
			timer := time.NewTimer(time.Duration(ep.warmupMinutes) * time.Minute)
			defer timer.Stop()

			<-timer.C

			ep.warmupComplete.Store(true)
			fmt.Printf("[WARMUP] ✅ Warm-up complete after %d minutes. Anomaly detection now active.\n", ep.warmupMinutes)

			// Optional: force one immediate baseline update with any collected normal events
			ep.TrainBaseline(context.Background())
		}()
	} else {
		ep.warmupComplete.Store(true) // no warm-up → immediately active
	}

	loopCtx, loopCancel := context.WithCancel(context.Background())
	ep.cancelLoops = loopCancel

	// === AUTO TRAINING TICKER (runs after warm-up) ===
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				if ep.warmupComplete.Load() {
					ep.TrainBaseline(loopCtx)
				}
			}
		}
	}()

	// Sliding window (you already had this)
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				ep.FeatureExtractor.resetWindow()
			}
		}
	}()

	return ep
}

func (ep *EventProcessor) Stop() {
	if ep.cancelLoops != nil {
		ep.cancelLoops()
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
	return fe.Extract(event)
}

func (ep *EventProcessor) toAIFeatureVector(features BehavioralFeatures, event SecurityEvent) ai.FeatureVector {
	return ai.FeatureVector{
		ProcessName:      features.ProcessName,
		ProcessFrequency: features.ProcessFrequency,
		SyscallCounts:    features.SyscallCount,
		FileAccessCount:  features.FileAccessCount,
		NetworkCount:     features.NetworkConnCount,
		SensitiveFiles:   len(features.SensitiveFiles),
		UserID:           features.UserID,
		TimeOfDay:        features.TimeOfDay,
		DayOfWeek:        features.DayOfWeek,
		ContainerAge:     features.ContainerAge,
		UniqueSyscalls:   len(features.SyscallCount),
	}
}
func (ep *EventProcessor) getAIRiskScore(features BehavioralFeatures, event SecurityEvent) float64 {
	if ep.AIClient == nil {
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

	return resp.Score
}

func (ep *EventProcessor) ProcessEvent(event SecurityEvent) (ProcessedEvent, error) {
	// Note: Removed atomic.AddInt64 here because worker() already does it.

	features := ep.FeatureExtractor.Extract(event)
	fmt.Printf("[PROC] Extracted features for %s | file_access=%d | sensitive=%d\n",
		features.ProcessName, features.FileAccessCount, len(features.SensitiveFiles))
	if !ep.warmupComplete.Load() {
		// During warm-up, treat all events as normal and buffer feature vectors.
		// The AutoTrain goroutine will call TrainBaseline when the timer fires.
		aiVec := ep.toAIFeatureVector(features, event)
		ep.bufferMu.Lock()
		if len(ep.normalBuffer) < 200 {
			ep.normalBuffer = append(ep.normalBuffer, aiVec)
		}
		ep.bufferMu.Unlock()

		return ProcessedEvent{
			Original:  event,
			Features:  features,
			Timestamp: time.Now(),
			RiskScore: 0.0,
			Anomaly:   false,
		}, nil
	}
	riskScore := ep.getAIRiskScore(features, event)

	isAnomaly := riskScore >= 0.5
	processedEvent := ProcessedEvent{
		Original:  event,
		Features:  features,
		Timestamp: time.Now(),
		RiskScore: riskScore,
		Anomaly:   isAnomaly,
	}

	if riskScore < 0.3 {
		aiVec := ep.toAIFeatureVector(features, event)
		ep.bufferMu.Lock()
		if len(ep.normalBuffer) < 200 {
			ep.normalBuffer = append(ep.normalBuffer, aiVec)
		}
		ep.bufferMu.Unlock()
	}

	if isAnomaly {
		atomic.AddInt64(&ep.Metrics.AnomaliesDetected, 1)
		if err := ep.storeForensicData(processedEvent); err != nil {
			atomic.AddInt64(&ep.Metrics.ErrorCount, 1)
			fmt.Printf("[FORENSICS ERROR] failed to store anomaly record: %v\n", err)
		}
	}

	return processedEvent, nil
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

// storeForensicData stores forensic information for anomalous events
func (ep *EventProcessor) storeForensicData(event ProcessedEvent) error {
	if ep.Vault == nil {
		fmt.Printf("ANOMALY DETECTED (vault not configured): Risk=%.2f, Rule=%s, Container=%s\n",
			event.RiskScore,
			event.Original.Rule,
			event.Original.Container.Name)
		return nil
	}

	record := buildForensicRecord(event.Original, event.Features, event.RiskScore, event.Timestamp)
	if ep.GeminiClient != nil && ep.GeminiClient.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		classification, err := ep.GeminiClient.ClassifyRecord(ctx, record)
		cancel()
		if err != nil {
			fmt.Printf("[GEMINI CLASSIFIER] classification failed, using deterministic incident type: %v\n", err)
		} else {
			if record.Metadata == nil {
				record.Metadata = map[string]interface{}{}
			}
			if classification.IncidentType != "" {
				record.Metadata["gemini_incident_type"] = classification.IncidentType
				if classification.IncidentType != record.IncidentType {
					record.Metadata["detected_incident_type"] = record.IncidentType
					record.IncidentType = classification.IncidentType
				}
			}
			record.Metadata["gemini_confidence"] = classification.Confidence
			record.Metadata["gemini_reason"] = classification.Reason
		}
	}
	return ep.Vault.StoreRecord(record)
}

// GetMetrics returns current processor metrics
func (ep *EventProcessor) GetMetrics() ProcessorMetrics {
	metrics := ProcessorMetrics{
		TotalEvents:       atomic.LoadInt64(&ep.Metrics.TotalEvents),
		ProcessedEvents:   atomic.LoadInt64(&ep.Metrics.ProcessedEvents),
		AnomaliesDetected: atomic.LoadInt64(&ep.Metrics.AnomaliesDetected),
		ErrorCount:        atomic.LoadInt64(&ep.Metrics.ErrorCount),
		AICalls:           atomic.LoadInt64(&ep.Metrics.AICalls),
	}
	return metrics
}

// FeatureExtractor extracts behavioral features from events
type FeatureExtractor struct {
	processFrequency map[string]int
	fileAccessCount  map[string]int
	networkConnCount map[string]int
	mu               sync.RWMutex
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		processFrequency: make(map[string]int),
		fileAccessCount:  make(map[string]int),
		networkConnCount: make(map[string]int),
	}
}

// resetWindow clears the current window counts (call every 5 minutes)
func (fe *FeatureExtractor) resetWindow() {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.processFrequency = make(map[string]int)
	fe.fileAccessCount = make(map[string]int)
	fe.networkConnCount = make(map[string]int)
	fmt.Println("[FEATURE] Sliding window reset – new baseline period started")
}

// Extract extracts behavioral features from a security event
// Extract extracts behavioral features from a security event
func (fe *FeatureExtractor) Extract(event SecurityEvent) BehavioralFeatures {
	features := BehavioralFeatures{
		SyscallCount:   make(map[string]int), // ← THIS WAS MISSING → panic
		SensitiveFiles: []string{},
		TimeWindow:     getTimeWindow(event.Timestamp),
		ContainerID:    event.Container.ID,
		Namespace:      event.Container.Namespace,
		PodName:        event.Container.PodName,
	}

	// Extract from output fields
	if event.Fields != nil {
		if proc, ok := event.Fields["proc.name"].(string); ok && proc != "" {
			features.ProcessName = proc
			fe.updateProcessFrequency(features.Namespace, event.Container.PodName, proc)
			features.ProcessFrequency = fe.getProcessFrequency(features.Namespace, event.Container.PodName, proc)

			// File access
			if fd_name, ok := event.Fields["fd.name"].(string); ok {
				fe.updateFileAccessCount(features.Namespace, event.Container.PodName, proc)
				features.FileAccessCount = fe.getFileAccessCount(features.Namespace, event.Container.PodName, proc)
				if isSensitiveFile(fd_name) {
					features.SensitiveFiles = append(features.SensitiveFiles, fd_name)
				}
			}

			// Network
			if _, ok := event.Fields["fd.sip"].(string); ok {
				fe.updateNetworkCount(features.Namespace, event.Container.PodName, proc)
				features.NetworkConnCount = fe.getNetworkCount(features.Namespace, event.Container.PodName, proc)
			}
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

		// === SyscallCount (safe now) ===
		if syscall, ok := event.Fields["evt.type"].(string); ok && syscall != "" {
			features.SyscallCount[syscall]++
		}
	}

	features.TimeOfDay = event.Timestamp.Hour()
	features.DayOfWeek = int(event.Timestamp.Weekday())

	// ContainerAge
	if startStr, ok := event.Fields["k8s.pod.startTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			features.ContainerAge = int(time.Since(t).Seconds() / 60)
		}
	}

	return features
}

// Helper methods

// Helper methods (updated for Issue 4)

func (fe *FeatureExtractor) updateProcessFrequency(namespace, pod, proc string) {
	if proc == "" {
		return
	}
	key := fmt.Sprintf("%s:%s:%s", namespace, pod, proc)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.processFrequency[key]++
}

func (fe *FeatureExtractor) getProcessFrequency(namespace, pod, proc string) int {
	if proc == "" {
		return 0
	}
	key := fmt.Sprintf("%s:%s:%s", namespace, pod, proc)
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.processFrequency[key]
}

// Same pattern for the other three counters
func (fe *FeatureExtractor) updateFileAccessCount(namespace, pod, proc string) {
	if proc == "" {
		return
	}
	key := fmt.Sprintf("%s:%s:%s", namespace, pod, proc)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.fileAccessCount[key]++
}

func (fe *FeatureExtractor) getFileAccessCount(namespace, pod, proc string) int {
	if proc == "" {
		return 0
	}
	key := fmt.Sprintf("%s:%s:%s", namespace, pod, proc)
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.fileAccessCount[key]
}

func (fe *FeatureExtractor) updateNetworkCount(namespace, pod, proc string) {
	if proc == "" {
		return
	}
	key := fmt.Sprintf("%s:%s:%s", namespace, pod, proc)
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.networkConnCount[key]++
}

func (fe *FeatureExtractor) getNetworkCount(namespace, pod, proc string) int {
	if proc == "" {
		return 0
	}
	key := fmt.Sprintf("%s:%s:%s", namespace, pod, proc)
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.networkConnCount[key]
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
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}
