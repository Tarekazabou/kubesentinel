package runtime

import (
	"testing"
	"time"

	"kubesentinel/internal/ai"
)

func TestEventProcessorStopStopsBackgroundLoops(t *testing.T) {
	client := ai.NewClient("http://127.0.0.1:65535", 0.5)
	ep := NewEventProcessor(0, client, 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ep.Stop()
		ep.Wait()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("event processor stop did not return in time")
	}
}
