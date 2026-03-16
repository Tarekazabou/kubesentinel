package runtime

import (
	"testing"
)

func BenchmarkEventPipeline(b *testing.B) {
	processor := NewEventProcessor(12) // Using your 12 workers
	event := SecurityEvent{
		Rule:   "Terminal shell in container",
		Fields: map[string]interface{}{"proc.cmdline": "cat /etc/shadow"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessEvent(event)
	}
}
