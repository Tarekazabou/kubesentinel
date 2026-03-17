package runtime

import (
	"sync"
	"testing"

	"kubesentinel/internal/ai"
)

func TestProcessorConcurrency(t *testing.T) {
	mockClient := &ai.Client{} // or initialize with appropriate mock/test client
	processor := NewEventProcessor(12, mockClient)
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
