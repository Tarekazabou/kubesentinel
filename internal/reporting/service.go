package reporting

import (
	"context"
	"fmt"
	"kubesentinel/internal/forensics"
	"time"
)

// ReportEnricher can enrich a deterministic report (e.g., with LLM narrative).
type ReportEnricher interface {
	EnrichReport(ctx context.Context, report Report, records []forensics.ForensicRecord) (Report, error)
}

// ServiceRequest defines report generation options.
type ServiceRequest struct {
	From       time.Time
	To         time.Time
	IncidentID string
}

// Service wires vault loading, report assembly, optional enrichment, and output generation.
type Service struct {
	Vault     *forensics.Vault
	Generator *Generator
	Enricher  ReportEnricher
}

func NewService(vault *forensics.Vault, generator *Generator, enricher ReportEnricher) *Service {
	return &Service{
		Vault:     vault,
		Generator: generator,
		Enricher:  enricher,
	}
}

func (s *Service) Generate(ctx context.Context, req ServiceRequest) (Report, error) {
	if s.Vault == nil {
		return Report{}, fmt.Errorf("vault is required")
	}
	if s.Generator == nil {
		return Report{}, fmt.Errorf("generator is required")
	}

	records, err := s.loadRecords(req)
	if err != nil {
		return Report{}, err
	}

	report := BuildReport(records, req.From, req.To)
	if s.Enricher != nil {
		enriched, enrichErr := s.Enricher.EnrichReport(ctx, report, records)
		if enrichErr != nil {
			fmt.Printf("[REPORT] Gemini enrichment failed, continuing with deterministic report: %v\n", enrichErr)
		} else {
			report = enriched
		}
	}

	if err := s.Generator.Generate(report); err != nil {
		return Report{}, err
	}

	return report, nil
}

func (s *Service) loadRecords(req ServiceRequest) ([]forensics.ForensicRecord, error) {
	if req.IncidentID != "" {
		record, err := s.Vault.GetRecord(req.IncidentID)
		if err != nil {
			return nil, fmt.Errorf("failed to load incident %s: %w", req.IncidentID, err)
		}
		return []forensics.ForensicRecord{*record}, nil
	}

	from := req.From
	to := req.To
	if from.IsZero() {
		from = time.Now().UTC().Add(-24 * time.Hour)
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}

	records, err := s.Vault.ListRecords(from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to list records: %w", err)
	}
	return records, nil
}
