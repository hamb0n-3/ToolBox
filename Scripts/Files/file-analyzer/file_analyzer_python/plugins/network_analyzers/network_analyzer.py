#!/usr/bin/env python3
# Network analyzer plugin

import re
import logging
from pathlib import Path
from typing import Dict, Set, Optional

from ..base_plugin import AnalyzerPlugin
from ...core.patterns import get_network_patterns


class NetworkAnalyzer(AnalyzerPlugin):
    """
    Plugin for analyzing network-related information in files.
    
    This plugin detects network protocols, security issues, configuration details,
    and other network-related information.
    """
    
    def __init__(self, config=None):
        """Initialize the network analyzer plugin."""
        super().__init__(config)
        
        # Get network-specific patterns
        self.network_patterns = get_network_patterns()
    
    @property
    def plugin_type(self) -> str:
        """Get the plugin type."""
        return 'network_analyzer'
    
    @property
    def supported_file_types(self) -> Set[str]:
        """Get supported file extensions."""
        return {'*'}  # Can analyze any file
    
    def can_analyze(self, file_path: Path, file_type: str, content: Optional[str] = None) -> bool:
        """
        Determine if this plugin can analyze the given file.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Optional content of the file if already loaded
            
        Returns:
            True if this plugin can analyze the file, False otherwise
        """
        # Can analyze any text file
        return file_type == 'text' or file_path.suffix.lower() in {
            '.json', '.js', '.py', '.java', '.php', '.ts', '.ini', '.conf', '.yaml', '.yml',
            '.xml', '.log', '.txt', '.html', '.md', '.sh', '.bash', 'Dockerfile'
        }
    
    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Analyze file content for network-related information.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Content of the file
            results: Existing results dictionary to update
            
        Returns:
            Updated results dictionary
        """
        logging.info(f"Analyzing network information in {file_path}")
        
        # Detect network protocols
        self._analyze_network_protocols(content, results)
        
        # Identify potential network security issues
        self._analyze_network_security_issues(content, results)
        
        # Extract network configuration details
        self._extract_network_configuration(content, results)
        
        # Correlate hosts and ports to identify endpoints
        self._correlate_network_endpoints(content, results)
        
        return results
    
    def _analyze_network_protocols(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Analyze content for network protocol indicators.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Get protocol patterns
        protocol_patterns = self.network_patterns.get('protocols', {})
        
        # Check for evidence of each protocol
        for protocol, pattern in protocol_patterns.items():
            if re.search(pattern, content):
                results['network_protocols'].add(protocol)
                logging.debug(f"Detected network protocol: {protocol}")
    
    def _analyze_network_security_issues(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Identify potential network security issues.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Get security issue patterns
        security_patterns = self.network_patterns.get('security_issues', {})
        
        # Check for potential security issues
        for issue, pattern in security_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # Calculate line number for better context
                line_no = content[:match.start()].count('\n') + 1
                
                # Extract surrounding context to help understand the finding
                # This grabs 20 characters before and after the match for context
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)].strip()
                
                # Format the finding with line number and context
                finding = f"{issue} (line {line_no}): {context}"
                results['network_security_issues'].add(finding)
                logging.debug(f"Detected network security issue: {issue} at line {line_no}")
    
    def _extract_network_configuration(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Extract network configuration details like ports and hostnames.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Extract ports
        if 'port' in self.network_patterns.get('configuration', {}):
            port_pattern = self.network_patterns['configuration']['port']
            port_matches = re.finditer(port_pattern, content)
            
            for match in port_matches:
                port = match.group(1)
                # Validate port number
                try:
                    port_number = int(port)
                    if 0 <= port_number <= 65535:  # Valid port range
                        results.setdefault('network_ports', set()).add(port)
                        
                        # Flag potentially sensitive ports
                        sensitive_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 27017}
                        if port_number in sensitive_ports:
                            service = self._get_port_service(port_number)
                            results['network_security_issues'].add(
                                f"Potentially sensitive port used: {port} (common for {service})"
                            )
                except ValueError:
                    continue
        
        # Extract hosts
        if 'host' in self.network_patterns.get('configuration', {}):
            host_pattern = self.network_patterns['configuration']['host']
            host_matches = re.finditer(host_pattern, content)
            
            for match in host_matches:
                host = match.group(1)
                results.setdefault('network_hosts', set()).add(host)
                
                # Check if the host is hardcoded to a specific IP (not localhost)
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) and not host.startswith(('127.', '192.168.', '10.')):
                    results['network_security_issues'].add(
                        f"Hardcoded non-local IP address: {host}"
                    )
    
    def _correlate_network_endpoints(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Correlate hosts and ports to identify network endpoints.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Get hosts and ports from results
        hosts = results.get('network_hosts', set())
        ports = results.get('network_ports', set())
        
        # If we have both hosts and ports, try to correlate them
        if hosts and ports:
            for host in hosts:
                for port in ports:
                    # Look for patterns where hosts and ports appear together
                    if re.search(rf'{re.escape(host)}.*?{port}|{port}.*?{re.escape(host)}', content, re.DOTALL):
                        results.setdefault('network_endpoints', set()).add(f"{host}:{port}")
    
    def _get_port_service(self, port: int) -> str:
        """
        Get common service name for a port number.
        
        Args:
            port: Port number
            
        Returns:
            Common service name for that port
        """
        # Map of common ports to their typical services
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alternate",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown Service") 