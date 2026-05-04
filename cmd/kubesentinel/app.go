package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"kubesentinel/internal/forensics"
	"kubesentinel/internal/llm"
	"kubesentinel/internal/reporting"
	"kubesentinel/internal/runtime"
	"kubesentinel/pkg/scanner"
)

type App struct{}

func NewApp() *App {
	return &App{}
}

func (a *App) runScan(cmd *cobra.Command, _ []string) {
	path, _ := cmd.Flags().GetString("path")
	format, _ := cmd.Flags().GetString("format")
	rulesPath, _ := cmd.Flags().GetString("rules")
	severity, _ := cmd.Flags().GetString("severity")

	if path == "" {
		fmt.Println("Error: --path is required. Example: --path ./deploy")
		os.Exit(1)
	}

	if rulesPath == "" {
		rulesPath = "./config/rules"
	}
	if severity == "" {
		severity = "medium"
	}

	fmt.Printf("Scanning manifests at: %s\n", path)
	fmt.Printf("Using rules from: %s\n", rulesPath)
	fmt.Printf("Minimum severity threshold: %s\n", severity)

	scnr, err := scanner.NewScanner(&scanner.ScanConfig{
		RulesPath:         rulesPath,
		SeverityThreshold: severity,
		OutputFormat:      format,
	})
	if err != nil {
		fmt.Printf("Failed to create scanner: %v\n", err)
		os.Exit(1)
	}

	results, err := scnr.ScanPath(path)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}

	violationsFound := false
	for _, r := range results {
		if !r.Passed {
			violationsFound = true
			fmt.Printf("Violations in %s:\n", r.FilePath)
			for _, v := range r.Violations {
				fmt.Printf("  - %s: %s\n", v.RuleID, v.Description)
			}
		}
	}

	if violationsFound {
		fmt.Println("\n❌ Scan completed with violations found!")
		os.Exit(2)
	}

	fmt.Println("\n✅ Scan completed successfully - no violations found!")
	os.Exit(0)
}

func (a *App) runMonitor(cmd *cobra.Command, _ []string) {
	namespace, _ := cmd.Flags().GetString("namespace")
	podFilter, _ := cmd.Flags().GetString("pod")
	deployment, _ := cmd.Flags().GetString("deployment")
	metricsPort, _ := cmd.Flags().GetString("metrics-port")
	if podFilter != "" {
		deployment = podFilter
	}

	workers, _ := cmd.Flags().GetInt("workers")
	buffer, _ := cmd.Flags().GetInt("buffer")
	source, _ := cmd.Flags().GetString("source")
	aiEndpoint, _ := cmd.Flags().GetString("ai-endpoint")
	warmupMinutes, _ := cmd.Flags().GetInt("warmup-minutes")
	if warmupMinutes < 0 {
		warmupMinutes = 0
	}

	if metricsPort != "" {
		startMetricsServer(metricsPort)
	}

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Loaded config:", viper.ConfigFileUsed())
		}
	}

	geminiEnabled := viper.GetBool("gemini.enabled")
	geminiClassifyRuntime := viper.GetBool("gemini.classify_runtime")
	geminiAPIKey := firstNonEmptyString(viper.GetString("gemini.api_key"), os.Getenv("GEMINI_API_KEY"))
	trainingAPIToken := firstNonEmptyString(viper.GetString("ai.training_api_token"), os.Getenv("TRAINING_API_TOKEN"))
	geminiModel := viper.GetString("gemini.model")
	if geminiModel == "" {
		geminiModel = "gemini-2.5-flash"
	}
	geminiTimeout := viper.GetInt("gemini.timeout_seconds")
	if geminiTimeout <= 0 {
		geminiTimeout = 15
	}

	if source == "" {
		source = viper.GetString("monitor.source")
	}
	if source == "" {
		source = "socket"
	}
	if aiEndpoint == "" {
		aiEndpoint = viper.GetString("ai.endpoint")
	}
	if trainingAPIToken != "" {
		_ = os.Setenv("TRAINING_API_TOKEN", trainingAPIToken)
	}

	monitorCfg := &runtime.MonitorConfig{
		FalcoSocket:           "/run/falco/falco.sock",
		BufferSize:            buffer,
		Workers:               workers,
		Namespace:             namespace,
		Deployment:            deployment,
		Source:                source,
		AIEndpoint:            aiEndpoint,
		PodName:               podFilter,
		VaultStoragePath:      viper.GetString("forensics.storage_path"),
		VaultRetentionDays:    viper.GetInt("forensics.retention_days"),
		VaultMaxSizeMB:        viper.GetInt("forensics.max_size_mb"),
		VaultCompression:      viper.GetBool("forensics.compression"),
		GeminiEnabled:         geminiEnabled,
		GeminiAPIKey:          geminiAPIKey,
		GeminiModel:           geminiModel,
		GeminiTimeoutSeconds:  geminiTimeout,
		GeminiClassifyRuntime: geminiClassifyRuntime,
		WarmupMinutes:         warmupMinutes,
	}

	monitor, err := runtime.NewMonitor(monitorCfg)
	if err != nil {
		fmt.Printf("Failed to create monitor: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting monitor in %s mode... (Gemini enabled=%v, classify_runtime=%v)\n",
		source, geminiEnabled, geminiClassifyRuntime)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\nReceived shutdown signal...")
		monitor.Stop()
		os.Exit(0)
	}()

	if err := monitor.Start(); err != nil {
		fmt.Printf("Monitor failed: %v\n", err)
		os.Exit(1)
	}

	monitor.Wait()
}

func (a *App) runReport(cmd *cobra.Command, _ []string) {
	fromArg, _ := cmd.Flags().GetString("from")
	toArg, _ := cmd.Flags().GetString("to")
	incidentID, _ := cmd.Flags().GetString("incident-id")
	formatArg, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")
	noLLM, _ := cmd.Flags().GetBool("no-llm")

	from, err := parseReportTime(fromArg)
	if err != nil {
		fmt.Printf("Invalid --from value: %v\n", err)
		os.Exit(1)
	}
	to, err := parseReportTime(toArg)
	if err != nil {
		fmt.Printf("Invalid --to value: %v\n", err)
		os.Exit(1)
	}

	vaultCfg := &forensics.VaultConfig{
		StoragePath:   viper.GetString("forensics.storage_path"),
		RetentionDays: viper.GetInt("forensics.retention_days"),
		MaxSizeMB:     viper.GetInt("forensics.max_size_mb"),
		Compression:   viper.GetBool("forensics.compression"),
	}
	if vaultCfg.StoragePath == "" {
		vaultCfg.StoragePath = "./forensics"
	}
	if vaultCfg.RetentionDays <= 0 {
		vaultCfg.RetentionDays = 90
	}
	if vaultCfg.MaxSizeMB <= 0 {
		vaultCfg.MaxSizeMB = 1000
	}

	vault, err := forensics.NewVault(vaultCfg)
	if err != nil {
		fmt.Printf("Failed to initialize vault: %v\n", err)
		os.Exit(1)
	}

	formats := parseFormats(formatArg)
	if len(formats) == 0 {
		formats = viper.GetStringSlice("reporting.formats")
	}
	if len(formats) == 0 {
		formats = []string{"markdown"}
	}

	if strings.TrimSpace(outputPath) == "" {
		outputPath = viper.GetString("reporting.output_path")
	}
	if strings.TrimSpace(outputPath) == "" {
		outputPath = "./reports"
	}

	generator := reporting.NewGenerator(&reporting.ReportConfig{
		OutputPath: outputPath,
		Formats:    formats,
	})

	var enricher reporting.ReportEnricher
	geminiEnabled := viper.GetBool("gemini.enabled") && !noLLM
	if geminiEnabled {
		geminiClient := llm.NewGeminiClient(llm.GeminiConfig{
			Enabled:        geminiEnabled,
			APIKey:         firstNonEmptyString(viper.GetString("gemini.api_key"), os.Getenv("GEMINI_API_KEY")),
			Model:          viper.GetString("gemini.model"),
			TimeoutSeconds: viper.GetInt("gemini.timeout_seconds"),
		})
		enricher = reporting.NewGeminiEnricher(geminiClient)
	}

	service := reporting.NewService(vault, generator, enricher)
	report, err := service.Generate(context.Background(), reporting.ServiceRequest{
		From:       from,
		To:         to,
		IncidentID: incidentID,
	})
	if err != nil {
		fmt.Printf("Report generation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Report generated successfully (ID: %s) in %s\n", report.ID, outputPath)
}
