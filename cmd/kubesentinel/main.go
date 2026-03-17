package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"kubesentinel/internal/runtime"
	"kubesentinel/pkg/scanner"
)

var (
	cfgFile string
	version = "0.1.0"
)

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

		// TODO: better output formatting + exit code based on violations
		for _, r := range results {
			if !r.Passed {
				fmt.Printf("Violations in %s:\n", r.FilePath)
				for _, v := range r.Violations {
					fmt.Printf("  - %s: %s\n", v.RuleID, v.Description)
				}
			}
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
	deployment, _ := cmd.Flags().GetString("deployment")
	workers, _ := cmd.Flags().GetInt("workers")
	buffer, _ := cmd.Flags().GetInt("buffer")
	source, _ := cmd.Flags().GetString("source")
	aiEndpoint, _ := cmd.Flags().GetString("ai-endpoint")

	// Allow config file or env to override
	if aiEndpoint == "" {
		aiEndpoint = viper.GetString("ai.endpoint")
	}
	if source == "" {
		source = viper.GetString("monitor.source")
	}
	if source == "" {
		source = "socket" // default
	}

	config := &runtime.MonitorConfig{
		FalcoSocket: "/run/falco/falco.sock",
		BufferSize:  buffer,
		Workers:     workers,
		Namespace:   namespace,
		Deployment:  deployment,
		Source:      source,
		AIEndpoint:  aiEndpoint, // ← now set here
	}

	monitor, err := runtime.NewMonitor(config)
	if err != nil {
		fmt.Printf("Failed to create monitor: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting monitor in %s mode...\n", source)

	// Graceful shutdown (unchanged)
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
	monitorCmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	monitorCmd.Flags().StringP("deployment", "d", "", "Deployment filter")
	monitorCmd.Flags().Int("workers", 4, "Number of processing workers")
	monitorCmd.Flags().Int("buffer", 10000, "Event channel buffer size")
	monitorCmd.Flags().String("source", "", "Event source: socket | stdin (default: socket)")
	monitorCmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI/ML service endpoint")
	// ── Important: duplicate the SAME flags for monitor-stdin ──
	monitorStdinCmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	monitorStdinCmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI/ML service endpoint")
	monitorStdinCmd.Flags().StringP("deployment", "d", "", "Deployment filter")
	monitorStdinCmd.Flags().Int("workers", 4, "Number of processing workers")
	monitorStdinCmd.Flags().Int("buffer", 10000, "Event channel buffer size")
	// report command (placeholder)
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate forensic reports (placeholder)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Report generation not yet implemented")
		},
	}

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
