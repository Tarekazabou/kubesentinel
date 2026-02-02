package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Monitor handles runtime security monitoring
type Monitor struct {
	Config     *MonitorConfig
	EventChan  chan SecurityEvent
	Processor  *EventProcessor
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// MonitorConfig holds monitoring configuration
type MonitorConfig struct {
	FalcoSocket string
	BufferSize  int
	Workers     int
	Namespace   string
	Deployment  string
}

// SecurityEvent represents a security event from Falco
type SecurityEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	Priority    string                 `json:"priority"`
	Rule        string                 `json:"rule"`
	Output      string                 `json:"output"`
	Source      string                 `json:"source"`
	Tags        []string               `json:"tags"`
	Fields      map[string]interface{} `json:"output_fields"`
	Container   ContainerInfo          `json:"container"`
}

// ContainerInfo contains container-specific information
type ContainerInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
}

// NewMonitor creates a new runtime monitor
func NewMonitor(config *MonitorConfig) (*Monitor, error) {
	ctx, cancel := context.WithCancel(context.Background())

	processor := NewEventProcessor(config.Workers)

	return &Monitor{
		Config:     config,
		EventChan:  make(chan SecurityEvent, config.BufferSize),
		Processor:  processor,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Start begins monitoring Falco events
func (m *Monitor) Start() error {
	fmt.Println("Starting runtime monitor...")

	// Start event processor workers
	m.Processor.Start(m.ctx, m.EventChan)

	// Connect to Falco socket
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.consumeFalcoEvents(); err != nil {
			fmt.Printf("Error consuming Falco events: %v\n", err)
		}
	}()

	// Start metrics collector
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.collectMetrics()
	}()

	return nil
}

// Stop gracefully stops the monitor
func (m *Monitor) Stop() error {
	fmt.Println("Stopping runtime monitor...")
	m.cancel()
	m.wg.Wait()
	close(m.EventChan)
	return nil
}

// consumeFalcoEvents reads events from Falco unix socket
func (m *Monitor) consumeFalcoEvents() error {
	// Connect to Falco socket
	conn, err := net.Dial("unix", m.Config.FalcoSocket)
	if err != nil {
		return fmt.Errorf("failed to connect to Falco socket: %w", err)
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for large events

	fmt.Println("Connected to Falco, consuming events...")

	for {
		select {
		case <-m.ctx.Done():
			return nil
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("scanner error: %w", err)
				}
				return nil // EOF
			}

			// Parse event
			event, err := m.parseEvent(scanner.Bytes())
			if err != nil {
				fmt.Printf("Warning: failed to parse event: %v\n", err)
				continue
			}

			// Filter by namespace/deployment if specified
			if !m.shouldProcessEvent(event) {
				continue
			}

			// Send to event channel (non-blocking)
			select {
			case m.EventChan <- event:
			default:
				fmt.Println("Warning: event channel full, dropping event")
			}
		}
	}
}

// parseEvent parses a Falco JSON event
func (m *Monitor) parseEvent(data []byte) (SecurityEvent, error) {
	var event SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return event, err
	}
	return event, nil
}

// shouldProcessEvent checks if event should be processed based on filters
func (m *Monitor) shouldProcessEvent(event SecurityEvent) bool {
	// Filter by namespace
	if m.Config.Namespace != "" && event.Container.Namespace != m.Config.Namespace {
		return false
	}

	// Filter by deployment (check if pod name contains deployment name)
	if m.Config.Deployment != "" {
		if event.Container.PodName == "" || 
		   !contains(event.Container.PodName, m.Config.Deployment) {
			return false
		}
	}

	return true
}

// collectMetrics periodically collects and logs monitoring metrics
func (m *Monitor) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			metrics := m.Processor.GetMetrics()
			fmt.Printf("Metrics - Events: %d, Processed: %d, Anomalies: %d\n",
				metrics.TotalEvents,
				metrics.ProcessedEvents,
				metrics.AnomaliesDetected)
		}
	}
}

// Helper function
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
