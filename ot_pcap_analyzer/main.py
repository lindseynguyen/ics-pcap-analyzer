#!/usr/bin/env python3
"""
OT PCAP Analyzer - Main Entry Point
===================================
CLI and GUI entry points for OT/ICS network traffic analysis.
"""
import argparse
import sys

from .version import VERSION
from .utils import setup_logging, logger, timestamp
from .models import AnalyzerConfig
from .analyzer import OTAnalyzer


def run_cli(pcap_file: str, output: str = None, max_packets: int = None,
            enable_advanced: bool = False):
    """Run CLI analysis

    Args:
        pcap_file: Path to PCAP file
        output: Output Excel file path
        max_packets: Maximum packets to analyze
        enable_advanced: Enable correlation, baseline, and storyline features
    """
    setup_logging("INFO")
    logger.info(f"OT PCAP Analyzer v{VERSION}")
    logger.info(f"Analyzing: {pcap_file}")

    # Create config with optional advanced features
    config = AnalyzerConfig(
        detect_anomalies=True,
        track_assets=True,
        use_ml=True,
        enable_correlation=enable_advanced,
        enable_baseline=enable_advanced,
        enable_storyline=enable_advanced,
    )

    analyzer = OTAnalyzer(config)

    def progress_callback(current, total, message):
        if current % 1000 == 0:
            logger.info(message)

    analyzer.progress_callback = progress_callback

    try:
        analyzer.analyze_capture(pcap_file, max_packets)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Print summary
    summary = analyzer.get_summary()
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    for key, value in summary.items():
        if not isinstance(value, dict):
            print(f"  {key}: {value}")

    # Print attack chains if enabled
    if enable_advanced and hasattr(analyzer, 'attack_chains') and analyzer.attack_chains:
        print("\n" + "="*60)
        print(f"ATTACK CHAINS DETECTED: {len(analyzer.attack_chains)}")
        print("="*60)
        for chain in analyzer.attack_chains[:5]:
            print(f"  {chain.chain_id}: {chain.overall_severity} - {chain.phase_count} phases")

    print("="*60)

    # Export if output specified
    if output:
        try:
            analyzer.export_excel(output)
            print(f"\nReport exported: {output}")
        except Exception as e:
            logger.error(f"Export failed: {e}")
            import traceback
            traceback.print_exc()
    else:
        default_output = f"ot_security_report_{timestamp()}.xlsx"
        try:
            analyzer.export_excel(default_output)
            print(f"\nReport exported: {default_output}")
        except Exception as e:
            logger.error(f"Export failed: {e}")
            import traceback
            traceback.print_exc()

    return analyzer


def run_gui():
    """Run GUI application"""
    try:
        # Check PyQt5 availability
        try:
            from PyQt5.QtWidgets import QApplication
        except ImportError:
            print("Error: PyQt5 is not installed.")
            print("Please install it with: pip install PyQt5")
            sys.exit(1)

        # Import and run GUI
        from .gui import run_gui as start_gui
        start_gui()

    except Exception as e:
        print(f"Error: Could not start GUI. {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        prog="ot_pcap_analyzer",
        description=f"OT PCAP Analyzer v{VERSION} - Advanced OT/ICS Traffic Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Launch GUI (default)
  python -m ot_pcap_analyzer --gui

  # CLI analysis with basic detection
  python -m ot_pcap_analyzer --cli capture.pcap

  # CLI analysis with advanced features (attack chains, storylines)
  python -m ot_pcap_analyzer --cli capture.pcap --advanced

  # Specify output file
  python -m ot_pcap_analyzer --cli capture.pcap -o report.xlsx

  # Limit packet count
  python -m ot_pcap_analyzer --cli capture.pcap -m 100000
        """
    )

    parser.add_argument("--gui", action="store_true",
                       help="Launch GUI mode")
    parser.add_argument("--cli", type=str, metavar="PCAP",
                       help="Run CLI analysis on PCAP file")
    parser.add_argument("--output", "-o", type=str,
                       help="Output Excel file path")
    parser.add_argument("--max-packets", "-m", type=int,
                       help="Maximum packets to analyze")
    parser.add_argument("--advanced", action="store_true",
                       help="Enable advanced features (correlation, baseline, storyline)")
    parser.add_argument("--version", action="version",
                       version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    if args.cli:
        run_cli(args.cli, args.output, args.max_packets, args.advanced)
    elif args.gui:
        run_gui()
    else:
        # Default: launch GUI
        run_gui()


if __name__ == "__main__":
    main()