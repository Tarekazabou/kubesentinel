package main

import (
	"fmt"
	"os"
	"strings"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"kubesentinel/pkg/scanner"
)

var (
	cfgFile string
	version = "0.1.0"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "kubesentinel",
	Short: "Cloud Security Posture Management Framework",
	Long: `KubeSentinel is a high-performance security orchestration system that bridges 
static configuration security and dynamic runtime behavior monitoring for Kubernetes.`,
	Version: version,
}

// scanCmd handles static analysis of manifests
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform static analysis on Kubernetes manifests",
	Long: `Scan Kubernetes YAML files, Helm charts, and Dockerfiles for security 
misconfigurations before deployment.`,
	Run: func(cmd *cobra.Command, args []string) {
		path, _ := cmd.Flags().GetString("path")
		format, _ := cmd.Flags().GetString("format")
		rulesPath, _ := cmd.Flags().GetString("rules")
		severity, _ := cmd.Flags().GetString("severity") // optional – added for better control

		if path == "" {
			fmt.Println("Error: --path is required. Example: --path ./deploy")
			os.Exit(1)
		}

		// Default values if flags not provided
		if rulesPath == "" {
			rulesPath = "./config/custom-rules.yaml" // or "../config/custom-rules.yaml"
		}
		if severity == "" {
			severity = "medium"
		}

		fmt.Printf("Scanning manifests at: %s\n", path)
		fmt.Printf("Output format: %s\n", format)
		fmt.Printf("Using rules from: %s\n", rulesPath)
		fmt.Printf("Minimum severity threshold: %s\n", severity)

		// Prepare scanner configuration
		config := &scanner.ScanConfig{
			RulesPath:         rulesPath,
			SeverityThreshold: severity,
			OutputFormat:      format,
		}

		scnr, err := scanner.NewScanner(config)
		if err != nil {
			fmt.Printf("Error initializing scanner: %v\n", err)
			os.Exit(1)
		}

		results, err := scnr.ScanPath(path)
		if err != nil {
			fmt.Printf("Scan failed: %v\n", err)
			os.Exit(1)
		}

		// ────────────────────────────────
		// Simple human-readable output
		// You can later expand this to JSON / markdown / table
		// ────────────────────────────────
		var totalViolations int
		fmt.Println("\n┌───────────────────────────────┐")
		fmt.Println("│        Scan Results           │")
		fmt.Println("└───────────────────────────────┘")

		for _, result := range results {
			if len(result.Violations) == 0 {
				continue
			}

			fmt.Printf("\nFile: %s\n", result.FilePath)
			for _, v := range result.Violations {
				// Only show violations >= threshold
				if severityLevel(v.Severity) < severityLevel(severity) {
					continue
				}

				totalViolations++
				fmt.Printf("  [%s] %s\n", strings.ToUpper(v.Severity), v.Description)
				fmt.Printf("      Rule ID    : %s\n", v.RuleID)
				fmt.Printf("      Resource   : %s\n", v.Resource)
				fmt.Printf("      Remediation: %s\n", v.Remediation)
				if v.LineNumber > 0 {
					fmt.Printf("      Location   : line %d\n", v.LineNumber)
				}
				fmt.Println()
			}
		}

		if totalViolations == 0 {
			fmt.Println("\n✓ No violations found above severity threshold.")
			fmt.Println("   Your manifests look secure!")
		} else {
			fmt.Printf("\nFound %d violation(s) at or above %s severity.\n", totalViolations, strings.ToUpper(severity))
			fmt.Println("Please review and remediate before deployment.")
			os.Exit(1) // non-zero exit = useful for CI/CD
		}
	},
}

// Helper to compare severity levels (you can move this elsewhere later)
func severityLevel(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// monitorCmd handles runtime monitoring
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Start runtime monitoring of Kubernetes cluster",
	Long: `Monitor live security events from Falco and analyze behavioral patterns 
using AI-powered anomaly detection.`,
	Run: func(cmd *cobra.Command, args []string) {
		cluster, _ := cmd.Flags().GetString("cluster")
		namespace, _ := cmd.Flags().GetString("namespace")
		deployment, _ := cmd.Flags().GetString("deployment")

		fmt.Printf("Starting runtime monitoring...\n")
		fmt.Printf("Cluster: %s\n", cluster)
		if namespace != "" {
			fmt.Printf("Namespace: %s\n", namespace)
		}
		if deployment != "" {
			fmt.Printf("Deployment: %s\n", deployment)
		}

		// TODO: Implement runtime monitoring logic
		// This will be implemented in internal/runtime/monitor.go
	},
}

// reportCmd generates forensic reports
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate forensic investigation reports",
	Long:  `Generate detailed forensic reports from stored security events and incidents.`,
	Run: func(cmd *cobra.Command, args []string) {
		incidentID, _ := cmd.Flags().GetString("incident-id")
		format, _ := cmd.Flags().GetString("format")
		from, _ := cmd.Flags().GetString("from")
		to, _ := cmd.Flags().GetString("to")

		fmt.Printf("Generating report...\n")
		if incidentID != "" {
			fmt.Printf("Incident ID: %s\n", incidentID)
		} else {
			fmt.Printf("Time range: %s to %s\n", from, to)
		}
		fmt.Printf("Format: %s\n", format)

		// TODO: Implement report generation logic
		// This will be implemented in internal/reporting/generator.go
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	// Scan command flags
	scanCmd.Flags().StringP("path", "p", "./manifests", "Path to manifests directory")
	scanCmd.Flags().StringP("format", "f", "json", "Output format (json, yaml, markdown)")
	scanCmd.Flags().String("rules", "./config/rules", "Path to custom rules directory")
	scanCmd.Flags().String("severity", "medium", "Minimum severity threshold (low, medium, high, critical)")

	// Monitor command flags
	monitorCmd.Flags().String("cluster", "minikube", "Kubernetes cluster context")
	monitorCmd.Flags().StringP("namespace", "n", "", "Namespace to monitor (empty for all)")
	monitorCmd.Flags().StringP("deployment", "d", "", "Specific deployment to monitor")
	monitorCmd.Flags().Int("workers", 4, "Number of worker goroutines")
	monitorCmd.Flags().Int("buffer", 10000, "Event buffer size")

	// Report command flags
	reportCmd.Flags().String("incident-id", "", "Specific incident ID to report on")
	reportCmd.Flags().StringP("format", "f", "markdown", "Report format (json, markdown, html)")
	reportCmd.Flags().String("from", "", "Start date (YYYY-MM-DD)")
	reportCmd.Flags().String("to", "", "End date (YYYY-MM-DD)")
	reportCmd.Flags().StringP("output", "o", "./reports", "Output directory")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(monitorCmd)
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
