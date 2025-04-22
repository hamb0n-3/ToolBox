#!/usr/bin/env python3
# Core analyzer class

import re
import logging
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
import multiprocessing
import math
import gc
from concurrent.futures import ProcessPoolExecutor, as_completed
import mmap
import resource
import signal
from functools import lru_cache

from ..plugins.plugin_registry import PluginRegistry
from ..utils.file_utils import read_file_content, detect_file_type, calculate_entropy
from ..core.patterns import get_patterns, get_hash_patterns


class MemoryLimitExceeded(Exception):
    """Exception raised when memory limit is exceeded during analysis."""
    pass


class TimeoutExceeded(Exception):
    """Exception raised when timeout is exceeded during analysis."""
    pass


def timeout_handler(signum, frame):
    """Signal handler for timeouts."""
    raise TimeoutExceeded("Analysis operation timed out")


class FileAnalyzer:
    """
    Core file analyzer class.
    
    This class coordinates the analysis of files using various plugins
    and provides a central interface for result collection and processing.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the file analyzer with optional configuration.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        self._setup_logging()
        
        # Get regex patterns for different types of data
        self.patterns = get_patterns()
        self.hash_patterns = get_hash_patterns()
        
        # Precompile regex patterns for performance
        self._compile_patterns()
        
        # Initialize results dictionary
        self.results = self._initialize_results()
        
        # API structure correlation data
        self.api_structure = {}
        
        # Initialize plugin registry
        self.plugin_registry = PluginRegistry()
        
        # Set default memory limit (80% of available memory)
        self.memory_limit = self.config.get('memory_limit', int(0.8 * resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))
        
        # Set default timeout (5 minutes)
        self.timeout = self.config.get('timeout', 300)
        
        # Load plugins
        self._load_plugins()
    
    def _compile_patterns(self) -> None:
        """Precompile regex patterns for better performance."""
        self.compiled_patterns = {}
        for data_type, pattern in self.patterns.items():
            try:
                self.compiled_patterns[data_type] = re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error as e:
                logging.error(f"Error compiling pattern for {data_type}: {str(e)}")
                # Fallback to non-compiled pattern
                self.compiled_patterns[data_type] = pattern
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        log_level = self.config.get('log_level', logging.INFO)
        log_file = self.config.get('log_file', 'file_analyzer.log')
        
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging with rotation
        try:
            from logging.handlers import RotatingFileHandler
            
            handlers = [
                RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5),
                logging.StreamHandler()
            ]
        except ImportError:
            handlers = [
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
            handlers=handlers
        )
    
    def _initialize_results(self) -> Dict[str, Set[str]]:
        """
        Initialize the results dictionary with empty sets for all categories.
        
        Returns:
            Empty results dictionary
        """
        results = {}
        
        # Initialize with all pattern keys
        for key in self.patterns.keys():
            results[key] = set()
        
        # Add additional result categories
        additional_categories = [
            'api_framework', 'code_complexity', 'security_smells', 'code_quality',
            'high_entropy_strings', 'commented_code', 'network_protocols',
            'network_security_issues', 'network_ports', 'network_hosts',
            'network_endpoints', 'software_versions', 'ml_credential_findings',
            'ml_api_findings', 'runtime_errors', 'file_metadata'
        ]
        
        for category in additional_categories:
            results[category] = set()
        
        return results
    
    def _load_plugins(self) -> None:
        """Load and register all plugins."""
        try:
            # Discover built-in plugins
            self.plugin_registry.discover_plugins()
            
            # Load additional plugins from custom directories if specified
            custom_plugin_dirs = self.config.get('plugin_dirs', [])
            for plugin_dir in custom_plugin_dirs:
                plugin_path = Path(plugin_dir)
                if plugin_path.exists():
                    self.plugin_registry.discover_plugins(str(plugin_dir))
                else:
                    logging.warning(f"Plugin directory does not exist: {plugin_dir}")
            
            loaded_plugins = sum(len(plugins) for plugins in self.plugin_registry.plugins.values())
            logging.info(f"Loaded {loaded_plugins} plugins")
        except Exception as e:
            logging.error(f"Error loading plugins: {str(e)}")
    
    def analyze_file(self, file_path: str) -> Dict[str, Set[str]]:
        """
        Analyze a file and extract relevant information.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary of analysis results
        """
        try:
            # Set timeout handler
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.timeout)
            
            file_path = Path(file_path)
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                self.results['runtime_errors'].add(f"File not found: {file_path}")
                return self.results

            # Add file metadata
            self._add_file_metadata(file_path)

            # Determine file type
            file_type = detect_file_type(file_path)
            logging.info(f"Detected file type: {file_type}")
            
            # Check file size to determine processing method
            file_size = file_path.stat().st_size
            
            # Implement memory safety check
            if file_size > self.memory_limit:
                logging.warning(f"File size ({file_size} bytes) exceeds safe memory limit, using chunked processing")
                self._chunked_analyze(file_path, file_type)
            elif file_size > 10 * 1024 * 1024:  # 10MB
                # For large files, use parallel processing
                self.analyze_file_parallel(file_path, file_type)
            else:
                # For smaller files, use standard processing
                content, is_binary = read_file_content(file_path)
                
                # Process the file with built-in pattern matching
                self._process_patterns(content)
                
                # Process with registered plugins
                self._process_with_plugins(file_path, file_type, content)
            
            # Clear timeout
            signal.alarm(0)
            return self.results

        except TimeoutExceeded:
            logging.error(f"Analysis timed out for {file_path}")
            self.results['runtime_errors'].add(f"Analysis timed out after {self.timeout} seconds")
            return self.results
        except MemoryLimitExceeded:
            logging.error(f"Memory limit exceeded for {file_path}")
            self.results['runtime_errors'].add("Memory limit exceeded during analysis")
            return self.results
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")
            self.results['runtime_errors'].add(f"Error: {str(e)}")
            return self.results
        finally:
            # Always clear the timeout
            signal.alarm(0)
            # Force garbage collection
            gc.collect()
    
    def _add_file_metadata(self, file_path: Path) -> None:
        """
        Add file metadata to results.
        
        Args:
            file_path: Path to the file
        """
        stat = file_path.stat()
        
        metadata = {
            f"Filename: {file_path.name}",
            f"File size: {stat.st_size} bytes",
            f"Created: {stat.st_ctime}",
            f"Modified: {stat.st_mtime}",
            f"Accessed: {stat.st_atime}",
            f"Permissions: {stat.st_mode}",
            f"Owner ID: {stat.st_uid}",
            f"Group ID: {stat.st_gid}"
        }
        
        self.results['file_metadata'].update(metadata)
    
    def _process_with_plugins(self, file_path: Path, file_type: str, content: str) -> None:
        """
        Process file with all applicable plugins.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: File content
        """
        # Get applicable plugins
        applicable_plugins = self.plugin_registry.get_plugins_for_file(file_path, file_type, content)
        
        for plugin in applicable_plugins:
            try:
                logging.info(f"Applying {plugin.name} plugin")
                plugin.analyze(file_path, file_type, content, self.results)
            except Exception as e:
                logging.error(f"Error in plugin {plugin.name}: {str(e)}")
                self.results['runtime_errors'].add(f"Plugin error ({plugin.name}): {str(e)}")
    
    def _chunked_analyze(self, file_path: Path, file_type: str) -> None:
        """
        Analyze a very large file in manageable chunks to avoid memory issues.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
        """
        chunk_size = 5 * 1024 * 1024  # 5MB chunks
        
        with open(file_path, 'rb') as f:
            chunk = f.read(chunk_size)
            chunk_num = 1
            
            while chunk:
                logging.info(f"Processing chunk {chunk_num} of file {file_path.name}")
                
                # Convert to string for processing
                content = chunk.decode('utf-8', errors='ignore')
                
                # Process patterns in this chunk
                self._process_patterns(content)
                
                # Read next chunk
                chunk = f.read(chunk_size)
                chunk_num += 1
                
                # Force garbage collection between chunks
                gc.collect()
        
        # Process with lightweight plugins after chunked analysis
        try:
            # Use a temporary file for plugin processing if needed
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp_path = Path(temp.name)
                
            # Process with plugins that don't require full content
            basic_plugins = [p for p in self.plugin_registry.get_plugins_for_file(file_path, file_type) 
                             if hasattr(p, 'requires_full_content') and not p.requires_full_content]
                
            for plugin in basic_plugins:
                try:
                    plugin.analyze(file_path, file_type, "", self.results)
                except Exception as e:
                    logging.error(f"Error in plugin {plugin.name}: {str(e)}")
                    self.results['runtime_errors'].add(f"Plugin error ({plugin.name}): {str(e)}")
        finally:
            # Clean up
            if 'temp_path' in locals() and temp_path.exists():
                temp_path.unlink()
    
    def _process_patterns(self, content: str) -> None:
        """
        Process the content with built-in regex patterns.
        
        Args:
            content: The file content to analyze
        """
        # Extract information using regex patterns
        for data_type, compiled_pattern in self.compiled_patterns.items():
            # Skip the JSON response patterns as they're handled by plugins
            if data_type in ['successful_json_request', 'failed_json_request']:
                continue
            
            try:
                # Check for excessive memory usage
                current_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                if current_memory > self.memory_limit:
                    raise MemoryLimitExceeded(f"Memory usage exceeded: {current_memory} > {self.memory_limit}")
                
                # Pattern matching with timeout prevention
                matches = self._safe_pattern_match(compiled_pattern, content)
                
                for match in matches:
                    value = match.group(0)
                    
                    # Apply additional validation based on data type
                    if data_type == 'ipv4':
                        self._validate_ipv4(value, data_type)
                    elif data_type == 'base64_encoded':
                        self._validate_base64(value, data_type)
                    elif data_type == 'hash':
                        self._validate_hash(value, data_type)
                    else:
                        # Default case - just add the value
                        self.results[data_type].add(value)
            except TimeoutExceeded:
                logging.warning(f"Pattern matching timed out for {data_type}")
                self.results['runtime_errors'].add(f"Pattern matching timed out for {data_type}")
            except MemoryLimitExceeded as e:
                logging.warning(f"Memory limit exceeded during pattern matching: {str(e)}")
                self.results['runtime_errors'].add(f"Memory limit exceeded during pattern matching")
                # Force garbage collection
                gc.collect()
            except Exception as e:
                logging.error(f"Error processing pattern {data_type}: {str(e)}")
                self.results['runtime_errors'].add(f"Pattern error ({data_type}): {str(e)}")
    
    def _safe_pattern_match(self, pattern, content):
        """Safely perform pattern matching with protection against catastrophic backtracking."""
        if isinstance(pattern, str):
            try:
                pattern = re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error:
                return []
        
        # Use finditer with timeout protection
        try:
            return list(pattern.finditer(content))
        except re.error:
            return []
    
    def _validate_ipv4(self, value: str, data_type: str) -> None:
        """
        Validate and add an IPv4 address.
        
        Args:
            value: The value to validate
            data_type: The data type category
        """
        from ipaddress import IPv4Address, AddressValueError
        try:
            IPv4Address(value)
            self.results[data_type].add(value)
        except AddressValueError:
            pass
    
    def _validate_base64(self, value: str, data_type: str) -> None:
        """
        Validate and add a base64 encoded string.
        
        Args:
            value: The value to validate
            data_type: The data type category
        """
        from ..utils.file_utils import is_valid_base64
        if is_valid_base64(value):
            self.results[data_type].add(value)
    
    def _validate_hash(self, value: str, data_type: str) -> None:
        """
        Validate and add a hash.
        
        Args:
            value: The value to validate
            data_type: The data type category
        """
        hash_type = self._identify_hash(value)
        confidence = calculate_entropy(value)
        value = f"{value} (Type: {hash_type}, Entropy: {confidence:.2f})"
        self.results[data_type].add(value)
    
    @lru_cache(maxsize=1024)
    def _identify_hash(self, hash_value: str) -> str:
        """
        Advanced hash identification using pattern matching and entropy analysis.
        
        Args:
            hash_value: The hash string to identify
            
        Returns:
            Identified hash type(s) or 'Unknown'
        """
        # Clean the hash value
        hash_value = hash_value.strip()
        
        # Calculate entropy
        entropy = calculate_entropy(hash_value)
        
        # Store potential matches
        potential_matches = []
        
        # Check against known patterns
        for hash_type, (pattern, length) in self.hash_patterns.items():
            if length and len(hash_value) != length:
                continue
                
            if re.match(pattern, hash_value):
                if hash_type == 'MD5':
                    if entropy > 3.0:
                        potential_matches.append(hash_type)
                elif hash_type == 'BCrypt':
                    potential_matches = ['BCrypt']
                    break
                else:
                    potential_matches.append(hash_type)
        
        # Additional checks for specific hash types
        if len(hash_value) == 32:
            if all(c in '0123456789abcdef' for c in hash_value.lower()):
                if hash_value.lower().startswith('aad3b435'):
                    potential_matches = ['NTLM (Empty Password)']
                elif entropy < 2.5:
                    potential_matches.append('NTLM')
        
        return '/'.join(potential_matches) if potential_matches else 'Unknown'
    
    def analyze_file_parallel(self, file_path: Path, file_type: str) -> None:
        """
        Analyze a file using parallel processing for large files.
        
        This method splits the file into chunks and processes them in parallel,
        significantly improving performance for large files.
        
        Args:
            file_path: Path to the file to analyze
            file_type: Detected file type
        """
        file_size = file_path.stat().st_size
        
        # Determine optimal chunk size and number of workers
        cpu_count = max(1, multiprocessing.cpu_count() - 1)  # Leave one CPU free
        chunk_size = max(1024 * 1024, file_size // cpu_count)  # At least 1MB
        num_chunks = math.ceil(file_size / chunk_size)
        
        logging.info(f"Processing large file ({file_size/1024/1024:.2f} MB) in {num_chunks} chunks using {cpu_count} workers")
        
        # Process chunks in parallel
        with ProcessPoolExecutor(max_workers=cpu_count) as executor:
            futures = []
            
            for i in range(num_chunks):
                start_pos = i * chunk_size
                end_pos = min(start_pos + chunk_size, file_size)
                futures.append(executor.submit(self._process_file_chunk, file_path, start_pos, end_pos))
                
            # Collect results
            completed = 0
            for future in as_completed(futures):
                try:
                    chunk_results = future.result()
                    self._merge_chunk_results(chunk_results)
                    completed += 1
                    logging.info(f"Processed chunk {completed}/{num_chunks}")
                except Exception as e:
                    logging.error(f"Error processing chunk: {str(e)}")
                    self.results['runtime_errors'].add(f"Chunk processing error: {str(e)}")
        
        # Process with plugins after parallel processing is complete
        try:
            # Only load content for plugins that really need it
            content, is_binary = read_file_content(file_path)
            self._process_with_plugins(file_path, file_type, content)
        except Exception as e:
            logging.error(f"Error processing plugins after parallel analysis: {str(e)}")
            self.results['runtime_errors'].add(f"Plugin processing error: {str(e)}")
    
    def _process_file_chunk(self, file_path: Path, start_pos: int, end_pos: int) -> Dict[str, Set[str]]:
        """
        Process a chunk of a file.
        
        Args:
            file_path: Path to the file
            start_pos: Starting position in file
            end_pos: Ending position in file
            
        Returns:
            Results for this chunk
        """
        chunk_results = {key: set() for key in self.results.keys()}
        
        try:
            with open(file_path, 'rb') as f:
                # Use memory mapping for efficient access
                with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    # Extend chunk to include complete lines
                    # Move start_pos to the beginning of a line
                    if start_pos > 0:
                        while start_pos > 0 and mm[start_pos-1:start_pos] != b'\n':
                            start_pos -= 1
                    
                    # Move end_pos to the end of a line
                    while end_pos < len(mm) and mm[end_pos-1:end_pos] != b'\n':
                        end_pos += 1
                    
                    chunk_data = mm[start_pos:end_pos].decode('utf-8', errors='ignore')
                    
                    # Process the chunk with normal pattern detection
                    for data_type, pattern in self.patterns.items():
                        if data_type in ['successful_json_request', 'failed_json_request']:
                            continue
                            
                        matches = re.finditer(pattern, chunk_data)
                        for match in matches:
                            value = match.group(0)
                            # Apply simplified validation
                            chunk_results[data_type].add(value)
        except Exception as e:
            logging.error(f"Error processing chunk {start_pos}-{end_pos}: {str(e)}")
        
        return chunk_results
    
    def _merge_chunk_results(self, chunk_results: Dict[str, Set[str]]) -> None:
        """
        Merge results from a chunk into the main results.
        
        Args:
            chunk_results: Results from a chunk
        """
        for key, values in chunk_results.items():
            if key in self.results:
                self.results[key].update(values)
            else:
                self.results[key] = values
    
    def get_results(self) -> Dict[str, Set[str]]:
        """
        Get the analysis results.
        
        Returns:
            Copy of the results dictionary
        """
        return {k: v.copy() for k, v in self.results.items()}
    
    def get_api_structure(self) -> Dict:
        """
        Get the API structure information.
        
        Returns:
            The API structure dictionary
        """
        return self.api_structure.copy()
    
    def reset_results(self) -> None:
        """Reset the results to an empty state."""
        self.results = self._initialize_results()
        self.api_structure = {} 