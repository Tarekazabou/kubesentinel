package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Monitor handles runtime security monitoring
type Monitor struct {
	Config    *MonitorConfig
	EventChan chan SecurityEvent
	Processor *EventProcessor
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	stopped   atomic.Bool
}

// MonitorConfig holds monitoring configuration
type MonitorConfig struct {
	FalcoSocket string
	BufferSize  int
	Workers     int
	Namespace   string
	Deployment  string
	Source      string // "socket" or "stdin"
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

	processor := NewEventProcessor(config.Workers)

	return &Monitor{
		Config:    config,
		EventChan: make(chan SecurityEvent, config.BufferSize),
		Processor: processor,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func (m *Monitor) Start() error {
	fmt.Println("Starting runtime monitor...")

	m.Processor.Start(m.ctx, m.EventChan)

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		switch m.Config.Source {
		case "stdin":
			m.consumeFromStdin()
		default:
			m.consumeFromSocket()
		}
	}()

	go m.collectMetrics()

	return nil
}

func (m *Monitor) consumeFromSocket() {
	for {
		conn, err := net.Dial("unix", m.Config.FalcoSocket)
		if err != nil {
			fmt.Printf("Failed to connect to Falco socket %s: %v\n", m.Config.FalcoSocket, err)
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Printf("Connected to Falco socket: %s\n", m.Config.FalcoSocket)

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
			case m.EventChan <- event:
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
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' || line[0] == '\n' {
			continue
		}

		event, err := m.parseEvent(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Parse error: %v  → line: %s\n", err, string(line))
			continue
		}

		if !m.shouldProcessEvent(event) {
			continue
		}

		select {
		case m.EventChan <- event:
		default:
			fmt.Fprintln(os.Stderr, "Event channel full → dropping event")
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Stdin read error: %v\n", err)
	}

	fmt.Println("stdin closed → stopping monitor")
	m.cancel()
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
	if m.Config.Namespace != "" && event.Container.Namespace != m.Config.Namespace {
		return false
	}

	if m.Config.Deployment != "" {
		if event.Container.PodName == "" || !strings.Contains(event.Container.PodName, m.Config.Deployment) {
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
			metrics := m.Processor.GetMetrics()
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
	close(m.EventChan)
}

func (m *Monitor) Wait() {
	m.wg.Wait()
}

// contains is a simple substring check (you already had a version)
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
