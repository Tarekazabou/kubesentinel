package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"kubesentinel/internal/forensics"
	"kubesentinel/internal/llm"
	"kubesentinel/internal/reporting"
	"kubesentinel/internal/runtime"
	"kubesentinel/pkg/scanner"
)

var (
	cfgFile string
	version = "0.1.0"
)

// ============== PROMETHEUS METRICS ==============
var (
	falcoEventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubesentinel_falco_events_total",
			Help: "Total number of Falco events processed",
		},
		[]string{"severity"},
	)

	anomaliesDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubesentinel_anomalies_detected_total",
			Help: "Total number of anomalies detected",
		},
		[]string{"severity", "type"},
	)

	monitorDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kubesentinel_event_process_duration_seconds",
			Help:    "Time taken to process security events (in seconds)",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"event_type"},
	)

	scanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kubesentinel_scan_duration_seconds",
			Help:    "Time taken to scan manifests (in seconds)",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10},
		},
		[]string{"status"},
	)

	acctiveConnections int64
)

func init() {
	prometheus.MustRegister(falcoEventsProcessed)
	prometheus.MustRegister(anomaliesDetected)
	prometheus.MustRegister(monitorDuration)
	prometheus.MustRegister(scanDuration)
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "kubesentinel_active_connections",
			Help: "Number of active client connections",
		},
		func() float64 { return float64(atomic.LoadInt64(&acctiveConnections)) },
	))
}

func startMetricsServer(port string) {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	go func() {
		fmt.Printf("📊 Prometheus metrics available at http://0.0.0.0:%s/metrics\n", port)
		if err := http.ListenAndServe(":" + port, nil); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()
}

var rootCmd = &cobra.Command{
	Use:   "kubesentinel",
	Short: "Cloud Security Posture Management Framework",
	Long: `KubeSentinel is a high-performance security orchestration system that bridges 
static configuration security and dynamic runtime behavior monitoring for Kubernetes.`,
	Version: version,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform static analysis on Kubernetes manifests",
	Long: `Scan Kubernetes YAML files, Helm charts, and Dockerfiles for security 
misconfigurations before deployment.`,
	Run: func(cmd *cobra.Command, args []string) {
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

		config := &scanner.ScanConfig{
			RulesPath:         rulesPath,
			SeverityThreshold: severity,
			OutputFormat:      format,
		}

		scnr, err := scanner.NewScanner(config)
		if err != nil {
			fmt.Printf("Failed to create scanner: %v\n", err)
			os.Exit(1)
		}

		results, err := scnr.ScanPath(path)
		if err != nil {
			fmt.Printf("Scan failed: %v\n", err)
			os.Exit(1)
		}

		// Check for violations and exit with appropriate code
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

		// Exit with code 2 if violations found, 0 if all passed
		if violationsFound {
			fmt.Println("\n❌ Scan completed with violations found!")
			os.Exit(2)
		} else {
			fmt.Println("\n✅ Scan completed successfully - no violations found!")
			os.Exit(0)
		}
	},
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor runtime security events from Falco",
	Run:   runMonitor,
}

var monitorStdinCmd = &cobra.Command{
	Use:   "monitor-stdin",
	Short: "Monitor Falco events from stdin (kubectl logs pipe)",
	Long:  `Reads JSON-formatted Falco events from standard input. Useful when piping kubectl logs -f`,
	Run: func(cmd *cobra.Command, args []string) {
		viper.Set("monitor.source", "stdin")
		runMonitor(cmd, args)
	},
}

func runMonitor(cmd *cobra.Command, args []string) {
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

	// Start metrics server early
	if metricsPort != "" {
		startMetricsServer(metricsPort)
	}

	// Force reload config if --config flag was given
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Loaded config:", viper.ConfigFileUsed())
		}
	}

	// Load Gemini settings reliably
	geminiEnabled := viper.GetBool("gemini.enabled")
	geminiClassifyRuntime := viper.GetBool("gemini.classify_runtime")
	geminiAPIKey := firstNonEmptyString(viper.GetString("gemini.api_key"), os.Getenv("GEMINI_API_KEY"))
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

	config := &runtime.MonitorConfig{
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
	}

	monitor, err := runtime.NewMonitor(config)
	if err != nil {
		fmt.Printf("Failed to create monitor: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting monitor in %s mode... (Gemini enabled=%v, classify_runtime=%v)\n",
		source, geminiEnabled, geminiClassifyRuntime)

	// Graceful shutdown
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

func runReport(cmd *cobra.Command, args []string) {
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

func parseReportTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD")
}

func parseFormats(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.ToLower(strings.TrimSpace(part))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	// scan command flags
	scanCmd.Flags().StringP("path", "p", "", "Path to manifests directory")
	scanCmd.Flags().StringP("format", "f", "json", "Output format (json, yaml, markdown)")
	scanCmd.Flags().String("rules", "./config/rules", "Path to custom rules directory")
	scanCmd.Flags().String("severity", "medium", "Minimum severity threshold (low, medium, high, critical)")

	// monitor command flags
	// monitor command flags
	monitorCmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	monitorCmd.Flags().StringP("pod", "p", "", "Pod name filter (exact or substring)")
	monitorCmd.Flags().StringP("deployment", "d", "", "Deployment filter (substring)")
	monitorCmd.Flags().Int("workers", 4, "Number of processing workers")
	monitorCmd.Flags().Int("buffer", 10000, "Event channel buffer size")
	monitorCmd.Flags().String("source", "", "Event source: socket | stdin (default: socket)")
	monitorCmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI/ML service endpoint")
	monitorCmd.Flags().String("metrics-port", "8080", "Prometheus metrics server port (empty to disable)")

	// monitor-stdin command flags (duplicate for consistency)
	monitorStdinCmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	monitorStdinCmd.Flags().StringP("pod", "p", "", "Pod name filter (exact or substring)")
	monitorStdinCmd.Flags().StringP("deployment", "d", "", "Deployment filter (substring)")
	monitorStdinCmd.Flags().Int("workers", 4, "Number of processing workers")
	monitorStdinCmd.Flags().Int("buffer", 10000, "Event channel buffer size")
	monitorStdinCmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI/ML service endpoint")
	monitorStdinCmd.Flags().String("metrics-port", "8080", "Prometheus metrics server port (empty to disable)")
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate forensic investigation reports",
		Run:   runReport,
	}
	reportCmd.Flags().String("from", "", "Start time (RFC3339 or YYYY-MM-DD)")
	reportCmd.Flags().String("to", "", "End time (RFC3339 or YYYY-MM-DD)")
	reportCmd.Flags().String("incident-id", "", "Specific incident/record ID")
	reportCmd.Flags().String("format", "", "Output format(s): markdown,json,html (comma-separated)")
	reportCmd.Flags().String("output", "", "Output directory for generated reports")
	reportCmd.Flags().Bool("no-llm", false, "Disable Gemini enrichment even if enabled in config")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(monitorStdinCmd)
	rootCmd.AddCommand(reportCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.kubesentinel")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
