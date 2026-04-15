package runtime

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"kubesentinel/internal/ai"
)

func TestProcessorConcurrency(t *testing.T) {
	mockClient := &ai.Client{
		Endpoint:   "http://localhost:5000",
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		Threshold:  0.75,
	}
	processor := NewEventProcessor(12, mockClient, 0)
	event := SecurityEvent{
		Rule:   "Test Rule",
		Fields: map[string]interface{}{"proc.cmdline": "ls", "proc.pname": "sh"},
	}

	var wg sync.WaitGroup
	// Simulate 100 concurrent callers to the processor
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = processor.ProcessEvent(event)
		}()
	}
	wg.Wait()
}
