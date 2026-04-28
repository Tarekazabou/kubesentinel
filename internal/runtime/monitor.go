package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"kubesentinel/internal/ai"
	"kubesentinel/internal/forensics"
	"kubesentinel/internal/llm"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrEventChannelClosed = errors.New("event channel closed")

// Monitor handles runtime security monitoring *
type Monitor struct {
	config    *MonitorConfig
	eventChan chan SecurityEvent
	processor *EventProcessor
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	stopped   atomic.Bool
	closeOnce sync.Once
}

// MonitorConfig holds monitoring configuration
type MonitorConfig struct {
	FalcoSocket           string
	BufferSize            int
	Workers               int
	Namespace             string
	Deployment            string
	Source                string // "socket" or "stdin"
	AIEndpoint            string `json:"ai_endpoint"`
	PodName               string `json:"pod_name"` // ← NEW
	VaultStoragePath      string `json:"vault_storage_path"`
	VaultRetentionDays    int    `json:"vault_retention_days"`
	VaultMaxSizeMB        int    `json:"vault_max_size_mb"`
	VaultCompression      bool   `json:"vault_compression"`
	GeminiEnabled         bool   `json:"gemini_enabled"`
	GeminiAPIKey          string `json:"gemini_api_key"`
	GeminiModel           string `json:"gemini_model"`
	GeminiTimeoutSeconds  int    `json:"gemini_timeout_seconds"`
	GeminiClassifyRuntime bool   `json:"gemini_classify_runtime"`
	WarmupMinutes         int    `json:"warmup_minutes"` // default 10
}

// SecurityEvent represents a security event from Falco
type SecurityEvent struct {
	Timestamp time.Time              `json:"time"`
	Priority  string                 `json:"priority"`
	Rule      string                 `json:"rule"`
	Output    string                 `json:"output"`
	Source    string                 `json:"source"`
	Tags      []string               `json:"tags"`
	Fields    map[string]interface{} `json:"output_fields"`
	Container ContainerInfo          `json:"container"`
}

// ContainerInfo contains container-specific information
type ContainerInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
}

func NewMonitor(config *MonitorConfig) (*Monitor, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if config.Source == "" {
		config.Source = "socket"
	}
	if config.AIEndpoint == "" {
		config.AIEndpoint = "http://localhost:5000"
	}
	if config.VaultStoragePath == "" {
		config.VaultStoragePath = "./forensics"
	}
	if config.VaultRetentionDays <= 0 {
		config.VaultRetentionDays = 90
	}
	if config.VaultMaxSizeMB <= 0 {
		config.VaultMaxSizeMB = 1000
	}
	aiClient := ai.NewClient(config.AIEndpoint, 0.75)
	vault, err := forensics.NewVault(&forensics.VaultConfig{
		StoragePath:   config.VaultStoragePath,
		RetentionDays: config.VaultRetentionDays,
		MaxSizeMB:     config.VaultMaxSizeMB,
		Compression:   config.VaultCompression,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize forensic vault: %w", err)
	}

	processor := NewEventProcessor(config.Workers, aiClient, config.WarmupMinutes, vault)
	if config.GeminiEnabled && config.GeminiClassifyRuntime {
		processor.GeminiClient = llm.NewGeminiClient(llm.GeminiConfig{
			Enabled:        config.GeminiEnabled,
			APIKey:         config.GeminiAPIKey,
			Model:          config.GeminiModel,
			TimeoutSeconds: config.GeminiTimeoutSeconds,
		})
	}

	return &Monitor{
		config:    config,
		eventChan: make(chan SecurityEvent, config.BufferSize),
		processor: processor,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Config returns the monitor configuration.
func (m *Monitor) Config() *MonitorConfig {
	return m.config
}

// EventChan returns the runtime event channel.
func (m *Monitor) EventChan() chan SecurityEvent {
	return m.eventChan
}

// Processor returns the event processor.
func (m *Monitor) Processor() *EventProcessor {
	return m.processor
}
func (m *Monitor) Start() error {
	fmt.Println("Starting runtime monitor...")

	// 1. Start the processor workers
	// We wrap this in the Monitor's WaitGroup so we can wait for them during shutdown
	m.processor.Start(m.ctx, m.eventChan)
	if !m.processor.AIClient.HasAuthToken() {
		fmt.Println("ℹ️  TRAINING_API_TOKEN is not set; running AI endpoints in demo mode (auth disabled when server token is unset)")
	}

	if err := m.processor.AIClient.HealthCheck(m.ctx); err != nil {
		fmt.Printf("⚠️  AI service not reachable (will fallback to rules): %v\n", err)
	} else {
		fmt.Println("✅ AI service healthy – behavioral anomaly detection enabled")
	}

	// 2. Start source-specific event intake.
	switch m.config.Source {
	case "webhook":
		fmt.Println("Webhook source enabled. Waiting for HTTP /events payloads...")
	case "stdin":
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.consumeFromStdin()
		}()
	default:
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.consumeFromSocket()
		}()
	}

	go m.collectMetrics()

	return nil
}

func (m *Monitor) consumeFromSocket() {
	for {
		conn, err := net.Dial("unix", m.config.FalcoSocket)
		if err != nil {
			fmt.Printf("Failed to connect to Falco socket %s: %v\n", m.config.FalcoSocket, err)
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Printf("Connected to Falco socket: %s\n", m.config.FalcoSocket)

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			event, err := m.parseEvent(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
				continue
			}

			if !m.shouldProcessEvent(event) {
				continue
			}

			select {
			case m.eventChan <- event:
			default:
				fmt.Println("Warning: event channel full, dropping event")
			}
		}

		conn.Close()
		if err := scanner.Err(); err != nil {
			fmt.Printf("Scanner error: %v – reconnecting...\n", err)
		}
	}
}
func (m *Monitor) consumeFromStdin() {
	fmt.Println("Reading Falco JSON events from stdin... (pipe kubectl logs -f)")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := sanitizeStdinJSONLine(scanner.Text())
		if line == "" {
			continue
		}

		if _, err := m.ProcessJSONEvent([]byte(line)); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, ErrEventChannelClosed) {
				break
			}
			fmt.Fprintf(os.Stderr, "Event ingestion error (skipped): %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "stdin scanner error: %v\n", err)
	}

	fmt.Println("stdin closed → draining remaining events...")
	m.closeOnce.Do(func() { close(m.eventChan) })
	m.processor.Wait()
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Monitor shutdown complete.")
}

// sanitizeStdinJSONLine extracts one JSON object from a mixed log line.
// This supports kubectl logs streams that may include prefixes, timestamps, or ANSI/noise.
func sanitizeStdinJSONLine(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" {
		return ""
	}

	// Strip UTF-8 BOM when present.
	line = strings.TrimPrefix(line, "\uFEFF")

	start := strings.Index(line, "{")
	if start < 0 {
		return ""
	}
	line = line[start:]

	end := strings.LastIndex(line, "}")
	if end < 0 {
		return ""
	}
	line = line[:end+1]

	if !json.Valid([]byte(line)) {
		return ""
	}

	return line
}

// ProcessJSONEvent pushes a raw Falco JSON payload through the same parse/filter/enqueue pipeline.
func (m *Monitor) ProcessJSONEvent(data []byte) (bool, error) {
	event, err := m.parseEvent(data)
	if err != nil {
		return false, err
	}

	if !m.shouldProcessEvent(event) {
		return false, nil
	}

	select {
	case <-m.ctx.Done():
		return false, context.Canceled
	case m.eventChan <- event:
		return true, nil
	default:
		return false, fmt.Errorf("event buffer full")
	}
}

func (m *Monitor) parseEvent(data []byte) (SecurityEvent, error) {
	var event SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return event, err
	}

	if event.Fields != nil {
		// Essential for namespace filtering
		if ns, ok := event.Fields["k8s.ns.name"].(string); ok {
			event.Container.Namespace = ns
		}
		// Essential for deployment/pod filtering
		if pod, ok := event.Fields["k8s.pod.name"].(string); ok {
			event.Container.PodName = pod
		}
	}
	return event, nil
}

func (m *Monitor) shouldProcessEvent(event SecurityEvent) bool {
	// 1. Hard skip empty rules or internal Falco noise immediately
	if event.Rule == "" || strings.Contains(event.Rule, "Falco internal") {
		return false
	}

	// 2. Namespace must match (if set)
	if m.config.Namespace != "" && event.Container.Namespace != m.config.Namespace {
		return false
	}

	// 3. Pod must match (if set)
	if m.config.Deployment != "" {
		if event.Container.PodName == "" || !strings.Contains(event.Container.PodName, m.config.Deployment) {
			return false
		}
	}

	// 4. Skip empty or system-level processes that generate high volume
	if proc, ok := event.Fields["proc.name"].(string); ok {
		// Add "containerd" or "runc" if they are noisy in your environment
		if proc == "" || proc == "falco" || proc == "kubelet" {
			return false
		}
	}

	return true
}

func (m *Monitor) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			metrics := m.processor.GetMetrics()
			fmt.Printf("Metrics - Events: %d, Processed: %d, Anomalies: %d\n",
				metrics.TotalEvents,
				metrics.ProcessedEvents,
				metrics.AnomaliesDetected)
		}
	}
}

func (m *Monitor) Stop() {
	if m.stopped.Swap(true) {
		return
	}
	m.cancel()
	m.closeOnce.Do(func() { close(m.eventChan) })
}

func (m *Monitor) Wait() {
	m.wg.Wait()
}
