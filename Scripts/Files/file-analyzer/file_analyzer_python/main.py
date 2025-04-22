#!/usr/bin/env python3
# Main entry point for the file analyzer

import sys
import os
import argparse
import logging
import time
import traceback
from pathlib import Path
from typing import Dict, Any, Optional, List
import concurrent.futures

from .core.analyzer import FileAnalyzer
from .utils.dependency_checker import check_dependencies, generate_requirements_file, setup_colored_output
from .utils.output_formatter import (
    format_results, export_results_json, create_html_report, create_csv_report
)


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    # Create a colorful description for the help text
    colors = setup_colored_output()
    description = """
    File Analyzer - A comprehensive file analysis tool for cybersecurity
    
    This tool analyzes files to extract security-relevant information such as:
    - API endpoints and authentication details
    - Network information (IPs, domains, URLs)
    - Sensitive data (credentials, tokens, keys)
    - Code quality and security issues
    - And much more!
    """
    
    epilog = f"""examples:
  {colors['cyan']('Basic analysis:')}
    python -m file_analyzer example.js
    
  {colors['cyan']('Export to different formats:')}
    python -m file_analyzer example.js --json results.json --html report.html
    
  {colors['cyan']('Analyze multiple files:')}
    python -m file_analyzer file1.py file2.js file3.xml
    
  {colors['cyan']('Analyze a directory:')}
    python -m file_analyzer --dir ./project_folder
    
  {colors['cyan']('Specify custom configuration:')}
    python -m file_analyzer example.js --config my_config.json
    """
    
    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('file_paths', nargs='*', help='Path(s) to the file(s) to analyze')
    input_group.add_argument('--dir', help='Analyze all files in directory (recursively)')
    input_group.add_argument('--exclude', action='append', help='Exclude file pattern (glob syntax, can be used multiple times)')
    input_group.add_argument('--include', action='append', help='Include only file pattern (glob syntax, can be used multiple times)')
    input_group.add_argument('--max-size', type=int, default=50, help='Maximum file size to analyze in MB (default: 50)')
    input_group.add_argument('--max-files', type=int, default=1000, help='Maximum number of files to analyze (default: 1000)')
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--md', action='store_true', help='Output in markdown format (wrapped in triple backticks)')
    output_group.add_argument('--json', help='Export results to JSON file')
    output_group.add_argument('--html', help='Export results to HTML report')
    output_group.add_argument('--csv', help='Export results to CSV file')
    output_group.add_argument('--output-dir', help='Directory to store all output files')
    output_group.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    output_group.add_argument('--summary-only', action='store_true', help='Show only summary information')
    
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument('--skip-checks', action='store_true', help='Skip dependency checks (for advanced users)')
    config_group.add_argument('--requirements', action='store_true', help='Generate requirements.txt file and exit')
    config_group.add_argument('--version', action='store_true', help='Show version information and exit')
    config_group.add_argument('--config', help='Path to configuration file')
    config_group.add_argument('--plugin-dir', action='append', help='Additional plugin directory')
    config_group.add_argument('--parallel', type=int, default=0, 
                             help='Number of parallel workers (0=auto, default: auto)')
    
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--timeout', type=int, default=300, help='Analysis timeout in seconds per file (default: 300)')
    advanced_group.add_argument('--memory-limit', type=int, help='Memory limit in MB (default: auto)')
    advanced_group.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                                default='INFO', help='Set logging level (default: INFO)')
    advanced_group.add_argument('--log-file', default='file_analyzer.log', help='Log file path')
    
    return parser.parse_args()


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file if provided.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config = {}
    
    if config_path:
        import json
        try:
            config_path = Path(config_path)
            if not config_path.exists():
                logging.error(f"Configuration file not found: {config_path}")
                return config
                
            with open(config_path, 'r') as f:
                config = json.load(f)
            logging.info(f"Loaded configuration from {config_path}")
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {str(e)}")
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
    
    return config


def get_files_to_analyze(args) -> List[Path]:
    """
    Get list of files to analyze based on command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        List of file paths to analyze
    """
    files_to_analyze = []
    max_files = args.max_files
    max_size_bytes = args.max_size * 1024 * 1024  # Convert MB to bytes
    
    # Process individual files
    if args.file_paths:
        for file_path in args.file_paths:
            path = Path(file_path)
            if path.exists():
                if path.is_file():
                    if path.stat().st_size <= max_size_bytes:
                        files_to_analyze.append(path)
                    else:
                        logging.warning(f"Skipping {path}: exceeds maximum file size ({path.stat().st_size / 1024 / 1024:.2f} MB)")
                else:
                    logging.warning(f"Skipping {path}: not a file")
            else:
                logging.error(f"File not found: {path}")
    
    # Process directory recursively
    if args.dir:
        dir_path = Path(args.dir)
        if not dir_path.exists() or not dir_path.is_dir():
            logging.error(f"Directory not found: {dir_path}")
        else:
            # Create include/exclude patterns
            include_patterns = args.include if args.include else ["*"]
            exclude_patterns = args.exclude if args.exclude else []
            
            # Walk directory recursively
            for root, _, files in os.walk(dir_path):
                root_path = Path(root)
                
                for file in files:
                    file_path = root_path / file
                    
                    # Skip files that are too large
                    if file_path.stat().st_size > max_size_bytes:
                        logging.debug(f"Skipping {file_path}: exceeds maximum file size")
                        continue
                    
                    # Check include/exclude patterns
                    include_match = any(file_path.match(pattern) for pattern in include_patterns)
                    exclude_match = any(file_path.match(pattern) for pattern in exclude_patterns)
                    
                    if include_match and not exclude_match:
                        files_to_analyze.append(file_path)
                        
                        # Check if we've reached the maximum number of files
                        if len(files_to_analyze) >= max_files:
                            logging.warning(f"Reached maximum file limit ({max_files})")
                            break
                
                # Check again after processing each directory
                if len(files_to_analyze) >= max_files:
                    break
    
    return files_to_analyze


def analyze_files(files: List[Path], config: Dict[str, Any], args) -> Dict[str, Dict[str, set]]:
    """
    Analyze multiple files with progress tracking.
    
    Args:
        files: List of file paths to analyze
        config: Configuration dictionary
        args: Parsed command line arguments
        
    Returns:
        Dictionary mapping file paths to their analysis results
    """
    colors = setup_colored_output()
    results = {}
    total_files = len(files)
    
    # Determine number of workers for parallel processing
    num_workers = args.parallel
    if num_workers <= 0:
        import multiprocessing
        num_workers = max(1, multiprocessing.cpu_count() - 1)  # Leave one CPU free
    num_workers = min(num_workers, total_files)  # Don't use more workers than files
    
    if not args.quiet:
        print(f"\n{colors['bold']('Analyzing')} {total_files} files with {num_workers} workers...")
    
    if total_files == 0:
        return results
    
    # Use progress bar if available and not in quiet mode
    try:
        if not args.quiet:
            from tqdm import tqdm
            progress_bar = tqdm(total=total_files, desc="Analyzing files", unit="file")
        else:
            progress_bar = None
            
        # Create file analyzer instance
        analyzer = FileAnalyzer(config)
        
        if num_workers > 1 and total_files > 1:
            # Process files in parallel
            with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
                # Submit analysis tasks
                future_to_file = {
                    executor.submit(_analyze_single_file, file_path, config): file_path 
                    for file_path in files
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        file_results = future.result()
                        results[str(file_path)] = file_results
                    except Exception as e:
                        logging.error(f"Error analyzing {file_path}: {str(e)}")
                        results[str(file_path)] = {"error": {f"Error: {str(e)}"}}
                    
                    # Update progress bar
                    if progress_bar:
                        progress_bar.update(1)
        else:
            # Process files sequentially
            for file_path in files:
                try:
                    analyzer.reset_results()
                    analyzer.analyze_file(str(file_path))
                    results[str(file_path)] = analyzer.get_results()
                except Exception as e:
                    logging.error(f"Error analyzing {file_path}: {str(e)}")
                    results[str(file_path)] = {"error": {f"Error: {str(e)}"}}
                
                # Update progress bar
                if progress_bar:
                    progress_bar.update(1)
        
        # Close progress bar
        if progress_bar:
            progress_bar.close()
            
    except ImportError:
        # If tqdm is not available, fall back to simple output
        if not args.quiet:
            print(f"Analyzing {total_files} files...")
        
        analyzer = FileAnalyzer(config)
        
        for i, file_path in enumerate(files):
            try:
                if not args.quiet:
                    print(f"[{i+1}/{total_files}] Analyzing {file_path}...")
                
                analyzer.reset_results()
                analyzer.analyze_file(str(file_path))
                results[str(file_path)] = analyzer.get_results()
            except Exception as e:
                logging.error(f"Error analyzing {file_path}: {str(e)}")
                results[str(file_path)] = {"error": {f"Error: {str(e)}"}}
    
    return results


def _analyze_single_file(file_path, config):
    """
    Helper function for parallel file analysis.
    
    Args:
        file_path: Path to the file to analyze
        config: Configuration dictionary
        
    Returns:
        Analysis results dictionary
    """
    try:
        analyzer = FileAnalyzer(config)
        analyzer.analyze_file(str(file_path))
        return analyzer.get_results()
    except Exception as e:
        logging.error(f"Error analyzing {file_path}: {str(e)}")
        # Include traceback for debugging
        tb = traceback.format_exc()
        logging.debug(tb)
        return {"error": {f"Error: {str(e)}"}}


def generate_output_path(args, file_path: Path, extension: str) -> str:
    """
    Generate output file path based on input file and output directory.
    
    Args:
        args: Parsed command line arguments
        file_path: Input file path
        extension: Output file extension
        
    Returns:
        Output file path
    """
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        return str(output_dir / f"{file_path.stem}_analysis{extension}")
    else:
        return f"{file_path.stem}_analysis{extension}"


def export_all_results(all_results: Dict[str, Dict[str, set]], args):
    """
    Export results for all analyzed files based on command line arguments.
    
    Args:
        all_results: Dictionary mapping file paths to their analysis results
        args: Parsed command line arguments
    """
    colors = setup_colored_output()
    
    # Create output directory if specified
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each file's results
    for file_path_str, results in all_results.items():
        file_path = Path(file_path_str)
        
        # Generate output paths
        if args.json:
            if len(all_results) > 1:
                json_path = generate_output_path(args, file_path, ".json")
            else:
                json_path = args.json
            export_results_json(results, json_path)
        
        if args.html:
            if len(all_results) > 1:
                html_path = generate_output_path(args, file_path, ".html")
            else:
                html_path = args.html
            create_html_report(results, None, html_path)
        
        if args.csv:
            if len(all_results) > 1:
                csv_path = generate_output_path(args, file_path, ".csv")
            else:
                csv_path = args.csv
            create_csv_report(results, csv_path)
    
    # If we have multiple files, create a summary report
    if len(all_results) > 1:
        # TODO: Implement a summary report for multiple files
        logging.info("Multiple files analyzed, consider using --summary-only for overview")


def main():
    """Main entry point function."""
    start_time = time.time()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Get colored output formatter
    colors = setup_colored_output()
    
    # Show version info if requested
    if args.version:
        print(f"{colors['cyan']('File Analyzer v1.0.0')}")
        print(f"{colors['green']('Author:')} Tristan Pereira")
        print(f"{colors['green']('Description:')} A comprehensive file analysis tool for cybersecurity")
        sys.exit(0)
    
    # Generate requirements file if requested
    if args.requirements:
        generate_requirements_file()
        sys.exit(0)
    
    # Check dependencies unless explicitly skipped
    if not args.skip_checks:
        if not check_dependencies():
            sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Apply command line configurations
    config['log_level'] = getattr(logging, args.log_level.upper())
    config['log_file'] = args.log_file
    if args.plugin_dir:
        config['plugin_dirs'] = args.plugin_dir
    if args.timeout:
        config['timeout'] = args.timeout
    if args.memory_limit:
        config['memory_limit'] = args.memory_limit * 1024 * 1024  # Convert MB to bytes
    
    # Get files to analyze
    files_to_analyze = get_files_to_analyze(args)
    
    if not files_to_analyze:
        print(f"{colors['red']('Error: No files specified or found for analysis')}")
        print(f"Run with --help for usage information")
        sys.exit(1)
    
    # Analyze all files
    all_results = analyze_files(files_to_analyze, config, args)
    
    # Export results if requested
    export_all_results(all_results, args)
    
    # Print results to console if not in quiet mode
    if not args.quiet:
        # Calculate total findings
        total_findings = sum(
            sum(len(values) for key, values in results.items() 
                if isinstance(values, set) and key not in ['file_metadata', 'runtime_errors'])
            for results in all_results.values()
        )
        
        # Print summary
        elapsed_time = time.time() - start_time
        print(f"\n{colors['bold']('Analysis Complete')}")
        print(f"{colors['green']('Files analyzed:')} {len(all_results)}")
        print(f"{colors['green']('Total findings:')} {total_findings}")
        print(f"{colors['green']('Time elapsed:')} {elapsed_time:.2f} seconds")
        
        # Print detailed results for each file
        if not args.summary_only:
            for file_path_str, results in all_results.items():
                print(f"\n{colors['bold']('='*80)}")
                print(f"{colors['cyan']('Results for:')} {file_path_str}")
                print(f"{colors['bold']('='*80)}")
                
                # Format and print results
                formatted_results = format_results(results, None, args.md, colors)
                print(formatted_results)
    
    # Return success
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
