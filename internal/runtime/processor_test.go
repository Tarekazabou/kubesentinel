package runtime

import (
	"testing"

	"kubesentinel/internal/ai"
)

func BenchmarkEventPipeline(b *testing.B) {
	aiClient := &ai.Client{}                     // Initialize with appropriate configuration
	processor := NewEventProcessor(12, aiClient) // Using your 12 workers
	event := SecurityEvent{
		Rule:   "Terminal shell in container",
		Fields: map[string]interface{}{"proc.cmdline": "cat /etc/shadow"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessEvent(event)
	}
}
