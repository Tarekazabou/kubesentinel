package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	version = "0.1.0"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "kubesentinel",
	Short: "Cloud Security Posture Management Framework",
	Long: `KubeSentinel: Advanced Kubernetes Security Orchestration

KubeSentinel is a high-performance security orchestration system designed for Kubernetes environments.
It provides comprehensive security management by combining:

  STATIC ANALYSIS:
    - Scan manifests, Helm charts, and Dockerfiles for misconfigurations
  
  RUNTIME MONITORING:
    - Real-time security event detection and behavioral analysis
  
  FORENSIC REPORTING:
    - Detailed incident investigation and compliance reports

QUICK START:
  1. Scan manifests:    kubesentinel scan -p ./manifests
  2. Monitor cluster:   kubesentinel monitor --cluster minikube
  3. Generate reports:  kubesentinel report -f markdown -o ./reports

For more information on a specific command, use:
  kubesentinel [command] --help`,
	Version: version,
	Example: `  kubesentinel scan -p ./manifests -f json
  kubesentinel monitor --cluster production -n default
  kubesentinel report --incident-id INC-12345 -f markdown`,
}

// scanCmd handles static analysis of manifests
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform static analysis on Kubernetes manifests",
	Long: `Scan manifests for security misconfigurations BEFORE deployment.

This command analyzes Kubernetes YAML files, Helm charts, and Dockerfiles to identify
security vulnerabilities and misconfigurations early in your development pipeline.

CHECKS PERFORMED:
  - Insecure pod configurations (privileged, root user, unsafe capabilities)
  - Network policy violations and exposure risks
  - Secret management issues
  - Resource limits and requests misconfigurations
  - RBAC violations and overpermissioned service accounts
  - Image security concerns

OUTPUT FORMATS:
  json:     Machine-readable format for CI/CD integration
  yaml:     Structured YAML output
  markdown: Human-readable report format

SEVERITY LEVELS:
  low:      Minor security recommendations
  medium:   Moderate risks requiring attention
  high:     Significant security concerns
  critical: Severe vulnerabilities requiring immediate action`,
	Example: `  kubesentinel scan
  kubesentinel scan -p ./kubernetes/manifests -f json
  kubesentinel scan -p ./manifests --rules ./config/custom-rules.yaml --severity high
  kubesentinel scan -p ./helm/charts -f markdown > security-report.md`,
	Run: func(cmd *cobra.Command, args []string) {
		path, _ := cmd.Flags().GetString("path")
		format, _ := cmd.Flags().GetString("format")
		rulesPath, _ := cmd.Flags().GetString("rules")

		fmt.Printf("Scanning manifests at: %s\n", path)
		fmt.Printf("Output format: %s\n", format)
		fmt.Printf("Using rules from: %s\n", rulesPath)

		// TODO: Implement static scanning logic
		// This will be implemented in internal/static/scanner.go
	},
}

// monitorCmd handles runtime monitoring
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Start runtime monitoring of Kubernetes cluster",
	Long: `Monitor running Kubernetes clusters for real-time security threats.

This command continuously monitors live security events from Falco and other
Kubernetes security monitoring tools. It performs behavioral analysis and anomaly
detection to identify suspicious runtime activities.

MONITORING CAPABILITIES:
  - Real-time security event collection from Falco
  - Behavioral pattern analysis and anomaly detection
  - Process execution tracking and suspicious activity detection
  - Network anomaly detection
  - Configuration drift detection
  - Unauthorized access attempts and privilege escalation

PARAMETERS:
  cluster:    The Kubernetes cluster context to monitor
  namespace:  Optional - monitor specific namespace (empty for all)
  deployment: Optional - monitor specific deployment
  workers:    Number of concurrent workers for event processing (default: 4)
  buffer:     Event buffer size (default: 10000)

OUTPUT:
  Real-time events displayed in console with color-coded severity levels.
  Events are persisted for forensic analysis and reporting.`,
	Example: `  kubesentinel monitor --cluster production
  kubesentinel monitor --cluster staging -n payment-service
  kubesentinel monitor -d my-app --workers 8
  kubesentinel monitor --cluster dev-cluster -n default -d web-server`,
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
	Long: `Generate detailed forensic reports for incident investigation and compliance.

This command creates comprehensive forensic reports from stored security events
and incidents. Reports include timelines, root cause analysis, and recommendations
for remediation. Useful for security audits, compliance reviews, and incident response.

REPORT CONTENTS:
  - Incident timeline with event sequences
  - Affected resources and containers
  - User and service account actions
  - Network connections and anomalies
  - Configuration changes during incident
  - Remediation recommendations
  - Compliance findings

OUTPUT FORMATS:
  json:     Machine-readable format for programmatic processing
  markdown: Human-readable report with formatting
  html:     Interactive HTML report with visualizations

QUERY METHODS:
  By Incident ID: Get reports for specific incidents
  By Time Range:  Analyze events between specific dates

USAGE:
  Reports are stored in the configured output directory for archival and
  compliance purposes. Includes executive summary, detailed findings, and
  technical recommendations.`,
	Example: `  kubesentinel report --incident-id INC-20260210-001
  kubesentinel report --from 2026-02-01 --to 2026-02-10
  kubesentinel report -f html -o ./security-reports --incident-id INC-12345
  kubesentinel report -f markdown --from 2026-02-01 --to 2026-02-10 -o /var/reports`,
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
	scanCmd.Flags().String("rules", "./configs/rules", "Path to custom rules directory")
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
