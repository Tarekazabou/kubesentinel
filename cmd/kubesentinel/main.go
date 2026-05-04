package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	version = "0.1.0"
	app     = NewApp()
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

	activeConnections int64
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
		func() float64 { return float64(atomic.LoadInt64(&activeConnections)) },
	))
}

func startMetricsServer(port string) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	go func() {
		fmt.Printf("📊 Prometheus metrics available at http://0.0.0.0:%s/metrics\n", port)
		if err := http.ListenAndServe(":"+port, mux); err != nil && err != http.ErrServerClosed {
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
	Run: runScan,
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

func runMonitor(cmd *cobra.Command, args []string) { app.runMonitor(cmd, args) }

func runReport(cmd *cobra.Command, args []string) { app.runReport(cmd, args) }

func runScan(cmd *cobra.Command, args []string) { app.runScan(cmd, args) }

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

	addMonitorFlags(monitorCmd)
	addMonitorFlags(monitorStdinCmd)
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

func addMonitorFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	cmd.Flags().StringP("pod", "p", "", "Pod name filter (exact or substring)")
	cmd.Flags().StringP("deployment", "d", "", "Deployment filter (substring)")
	cmd.Flags().Int("workers", 4, "Number of processing workers")
	cmd.Flags().Int("buffer", 10000, "Event channel buffer size")
	cmd.Flags().String("source", "", "Event source: socket | stdin (default: socket)")
	cmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI/ML service endpoint")
	cmd.Flags().String("metrics-port", "8080", "Prometheus metrics server port (empty to disable)")
	cmd.Flags().Int("warmup-minutes", 10, "Minutes to collect baseline before enabling anomaly detection")
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
