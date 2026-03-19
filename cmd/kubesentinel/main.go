package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"kubesentinel/internal/runtime"
	"kubesentinel/pkg/scanner"
)

var (
	cfgFile string
	version = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:     "kubesentinel",
	Short:   "Cloud Security Posture Management Framework",
	Long:    "KubeSentinel bridges static config security and runtime monitoring for Kubernetes.",
	Version: version,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform static analysis on Kubernetes manifests",
	Run: func(cmd *cobra.Command, args []string) {
		path := viper.GetString("scan.path")
		format := viper.GetString("scan.format")
		rulesPath := viper.GetString("scan.rules")
		severity := viper.GetString("scan.severity")

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
	Short: "Monitor Falco events from stdin",
	Run: func(cmd *cobra.Command, args []string) {
		viper.Set("monitor.source", "stdin")
		runMonitor(cmd, args)
	},
}

func runMonitor(cmd *cobra.Command, args []string) {
	namespace := viper.GetString("monitor.namespace")
	podFilter := viper.GetString("monitor.pod")
	deployment := viper.GetString("monitor.deployment")

	if podFilter != "" {
		deployment = podFilter
	}

	config := &runtime.MonitorConfig{
		FalcoSocket: "/run/falco/falco.sock",
		BufferSize:  viper.GetInt("monitor.buffer"),
		Workers:     viper.GetInt("monitor.workers"),
		Namespace:   namespace,
		Deployment:  deployment,
		Source:      viper.GetString("monitor.source"),
		AIEndpoint:  viper.GetString("ai.endpoint"),
		PodName:     podFilter,
	}

	monitor, err := runtime.NewMonitor(config)
	if err != nil {
		fmt.Printf("Failed to create monitor: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting monitor in %s mode...\n", config.Source)

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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")

	// Scan flags
	scanCmd.Flags().StringP("path", "p", "", "Path to manifests")
	scanCmd.Flags().StringP("format", "f", "json", "Output format")
	scanCmd.Flags().String("rules", "./config/rules", "Rules directory")
	scanCmd.Flags().String("severity", "medium", "Severity threshold")

	// Monitor flags
	monitorCmd.Flags().StringP("namespace", "n", "", "Namespace filter")
	monitorCmd.Flags().StringP("pod", "p", "", "Pod filter")
	monitorCmd.Flags().StringP("deployment", "d", "", "Deployment filter")
	monitorCmd.Flags().Int("workers", 4, "Workers")
	monitorCmd.Flags().Int("buffer", 10000, "Buffer size")
	monitorCmd.Flags().String("source", "socket", "Source (socket|stdin)")
	monitorCmd.Flags().String("ai-endpoint", "http://localhost:5000", "AI endpoint")

	monitorStdinCmd.Flags().AddFlagSet(monitorCmd.Flags())

	// Bind flags to viper
	bindFlags("scan", scanCmd)
	bindFlags("monitor", monitorCmd)
	bindFlags("monitor", monitorStdinCmd)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(monitorStdinCmd)
}

func bindFlags(prefix string, cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		key := prefix + "." + f.Name
		viper.BindPFlag(key, f)
	})
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
