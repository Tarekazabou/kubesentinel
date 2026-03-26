package forensics

import "context"

// Collector enriches a forensic record with additional telemetry.
// Implementations can use eBPF, audit logs, Falco plugins, or flow logs.
type Collector interface {
	Enrich(ctx context.Context, record *ForensicRecord) error
}
