#!/usr/bin/env python3
"""
Main script for Log Analysis & CTI Tool with proper error handling
"""

import sys
import os
import argparse
from log_parser import LogParser
from cti_enricher import CTIEnricher
from ai_integration import AIIntegration
from report_generator import ReportGenerator


def parse_args(args=None):
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Log Analysis & CTI Tool')
    parser.add_argument('log_file', help='Path to the access log file', nargs='?')
    parser.add_argument('--output', '-o', default='reports',
                        help='Output directory for reports (default: reports/)')
    parser.add_argument('--ollama-model', '-om', default='llama3:latest',
                        help='Ollama model to use (default: llama3:latest)')
    parser.add_argument('--ollama-url', '-ou', default='http://localhost:11434',
                        help='Ollama server URL (default: http://localhost:11434)')
    parser.add_argument('--virustotal-key', '-vt',
                        help='VirusTotal API key')
    parser.add_argument('--abuseipdb-key', '-ab',
                        help='AbuseIPDB API key')
    parser.add_argument('--gui', action='store_true',
                        help='Launch GUI interface')

    if args is None:
        args = sys.argv[1:]

    return parser.parse_args(args)


def validate_file(file_path):
    """Validate that the file exists and is a supported type"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} was not found.")

    # Check if it's a supported file type
    supported_extensions = ['.log', '.txt', '.json']
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext not in supported_extensions:
        # Check if it might be a binary file by reading first few bytes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                # Check for common binary file signatures
                if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.exe', '.pdf']:
                    raise ValueError(f"File appears to be a {file_ext.upper()} file, not a log file.")
                # Check for binary content
                if b'\x00' in header:
                    raise ValueError("File appears to be binary, not a text log file.")
        except Exception as e:
            raise ValueError(f"Invalid file type: {str(e)}")

    return True


def main(args=None):
    """Main function that can be called with arguments"""
    parsed_args = parse_args(args)

    # Launch GUI if requested or no arguments provided
    if parsed_args.gui or (not parsed_args.log_file and len(sys.argv) == 1):
        try:
            # Try to import PySimpleGUI
            import PySimpleGUI as sg
            from gui import LogAnalysisGUI

            print("Launching GUI interface...")
            gui = LogAnalysisGUI()
            gui.run()
            return 0
        except ImportError as e:
            print(f"GUI requires PySimpleGUI. Error: {str(e)}")
            print("Install with: pip install PySimpleGUI")
            if not parsed_args.log_file:
                print("Please provide a log file or install PySimpleGUI for the GUI.")
                return 1
        except Exception as e:
            print(f"GUI error: {str(e)}")
            if not parsed_args.log_file:
                print("Please provide a log file.")
                return 1

    if not parsed_args.log_file:
        print("Error: No log file specified.")
        print("Usage: python main.py <log_file> [options]")
        print("       python main.py --gui (for graphical interface)")
        return 1

    try:
        # Validate file first
        validate_file(parsed_args.log_file)

        # Create output directory if it doesn't exist
        if not os.path.exists(parsed_args.output):
            os.makedirs(parsed_args.output)

        # Parse logs
        print("Parsing log file...")
        log_parser = LogParser(parsed_args.log_file)
        ip_activities = log_parser.parse()

        if not ip_activities:
            print("No IP activities found. The log file may be empty or in an unsupported format.")
            print("Supported formats: Common Log Format, Combined Log Format, JSON logs")
            return 1

        # Enrich with CTI data
        print("Enriching with CTI data...")
        cti_enricher = CTIEnricher(
            virustotal_api_key=parsed_args.virustotal_key,
            abuseipdb_api_key=parsed_args.abuseipdb_key
        )
        enriched_data = cti_enricher.enrich_ips(ip_activities)

        # Generate AI insights with Local Llama
        print("Initializing Local Llama AI...")
        ai_integration = AIIntegration(
            base_url=parsed_args.ollama_url,
            model=parsed_args.ollama_model
        )
        final_data = ai_integration.generate_insights(enriched_data)

        # Generate report
        print("Generating report...")
        report_generator = ReportGenerator()
        report_path = report_generator.generate(final_data, parsed_args.output)

        print(f"Analysis complete! Report saved to: {report_path}")
        return 0

    except FileNotFoundError as e:
        print(f"Error: {str(e)}")
        return 1
    except ValueError as e:
        print(f"Error: {str(e)}")
        print("Please provide a valid log file with one of these extensions: .log, .txt, .json")
        return 1
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())