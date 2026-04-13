package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"kubesentinel/internal/runtime"
)

var monitorWebhookCmd = &cobra.Command{
	Use:   "monitor-webhook",
	Short: "Run an HTTP webhook endpoint for Falco Sidekick events",
	Long:  "Starts a continuous HTTP server and ingests Falco JSON payloads from POST /events.",
	Run:   runMonitorWebhook,
}

func runMonitorWebhook(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetInt("port")
	namespace, _ := cmd.Flags().GetString("namespace")
	podFilter, _ := cmd.Flags().GetString("pod")
	deployment, _ := cmd.Flags().GetString("deployment")
	metricsPort, _ := cmd.Flags().GetString("metrics-port")
	workers, _ := cmd.Flags().GetInt("workers")
	buffer, _ := cmd.Flags().GetInt("buffer")
	aiEndpoint, _ := cmd.Flags().GetString("ai-endpoint")

	if podFilter != "" {
		deployment = podFilter
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
	geminiModel := viper.GetString("gemini.model")
	if geminiModel == "" {
		geminiModel = "gemini-2.5-flash"
	}
	geminiTimeout := viper.GetInt("gemini.timeout_seconds")
	if geminiTimeout <= 0 {
		geminiTimeout = 15
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
		Source:                "webhook",
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

	fmt.Printf("Starting monitor in webhook mode on port %d... (Gemini enabled=%v, classify_runtime=%v)\n",
		port, geminiEnabled, geminiClassifyRuntime)

	if err := monitor.Start(); err != nil {
		fmt.Printf("Monitor failed: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}

		queued, err := monitor.ProcessJSONEvent(body)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, runtime.ErrEventChannelClosed) {
				http.Error(w, "monitor shutting down", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, fmt.Sprintf("invalid event payload: %v", err), http.StatusBadRequest)
			return
		}

		if !queued {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("event ignored by filters"))
			return
		}

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("event accepted"))
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived shutdown signal...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		monitor.Stop()
	}()

	fmt.Printf("Webhook server listening on http://0.0.0.0:%d/events\n", port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Webhook server failed: %v\n", err)
		monitor.Stop()
		os.Exit(1)
	}

	monitor.Wait()
}

func init() {
	monitorWebhookCmd.Flags().Int("port", 8080, "Webhook server port")
	monitorWebhookCmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	monitorWebhookCmd.Flags().StringP("pod", "p", "", "Pod name filter (exact or substring)")
	monitorWebhookCmd.Flags().StringP("deployment", "d", "", "Deployment filter (substring)")
	monitorWebhookCmd.Flags().Int("workers", 4, "Number of processing workers")
	monitorWebhookCmd.Flags().Int("buffer", 10000, "Event channel buffer size")
	monitorWebhookCmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI/ML service endpoint")
	monitorWebhookCmd.Flags().String("metrics-port", "", "Prometheus metrics server port (empty to disable)")

	rootCmd.AddCommand(monitorWebhookCmd)
}
