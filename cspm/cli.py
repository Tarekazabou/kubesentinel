"""
CSPM CLI - Command-line interface for running the manifest scanner
"""

import argparse
import sys
from pathlib import Path
from cspm.manifest_scanner import scan_directory, scan_file
from cspm.report_generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description='KubeSentinel CSPM Scanner - Scan Kubernetes manifests for security misconfigurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m cspm.cli --manifest deploy/ --format html --output reports/report.html
  python -m cspm.cli --manifest deploy/secure-pod.yaml --format json
  python -m cspm.cli --manifest . --format json --output findings.json
        """
    )
    
    parser.add_argument(
        '--manifest',
        required=True,
        help='Path to Kubernetes manifest file or directory containing manifests'
    )
    
    parser.add_argument(
        '--format',
        default='json',
        choices=['json', 'html', 'text'],
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path (default: report.{format})'
    )
    
    parser.add_argument(
        '--summary',
        action='store_true',
        help='Print summary to console'
    )
    
    args = parser.parse_args()
    
    # Validate manifest path
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"Error: Manifest path does not exist: {args.manifest}", file=sys.stderr)
        sys.exit(1)
    
    # Scan manifests
    try:
        if manifest_path.is_dir():
            print(f"Scanning directory: {args.manifest}")
            findings = scan_directory(str(manifest_path))
        else:
            print(f"Scanning file: {args.manifest}")
            findings = scan_file(str(manifest_path))
    except Exception as e:
        print(f"Error scanning manifests: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Generate report
    reporter = ReportGenerator(findings)
    
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        output_path = f"report.{args.format}"
    
    # Generate report in requested format
    try:
        if args.format == 'json':
            reporter.generate_json(output_path)
            print(f"✓ JSON report generated: {output_path}")
        elif args.format == 'html':
            reporter.generate_html(output_path)
            print(f"✓ HTML report generated: {output_path}")
        elif args.format == 'text':
            summary = reporter.get_summary_text()
            with open(output_path, 'w') as f:
                f.write(summary)
            print(f"✓ Text report generated: {output_path}")
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Print summary to console if requested
    if args.summary:
        print(reporter.get_summary_text())
    
    # Return exit code based on findings
    summary = reporter._get_summary()
    if summary['CRITICAL'] > 0:
        print(f"\n⚠️  Found {summary['CRITICAL']} CRITICAL issues", file=sys.stderr)
        sys.exit(2)
    elif summary['HIGH'] > 0:
        print(f"\n⚠️  Found {summary['HIGH']} HIGH severity issues", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n✓ Scan complete. {summary['total']} issues found.")
        sys.exit(0)


if __name__ == '__main__':
    main()
