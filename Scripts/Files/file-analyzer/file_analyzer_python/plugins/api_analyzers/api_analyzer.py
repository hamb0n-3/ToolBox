#!/usr/bin/env python3
# API analyzer plugin

import re
import logging
from pathlib import Path
from typing import Dict, Set, Optional, Tuple, Any

from ..base_plugin import AnalyzerPlugin
from ...core.patterns import get_patterns

class APIAnalyzer(AnalyzerPlugin):
    """
    Plugin for analyzing API endpoints, patterns, and related information.
    
    This plugin extracts API structure, detects API frameworks, and correlates
    API endpoints with methods, parameters, and responses.
    """
    
    def __init__(self, config=None):
        """Initialize the API analyzer plugin."""
        super().__init__(config)
        
        # Get API-related patterns
        all_patterns = get_patterns()
        self.api_patterns = {k: v for k, v in all_patterns.items() if any(
            keyword in k for keyword in ['api', 'endpoint', 'webhook', 'graphql', 'rest']
        )}
        
        # Add patterns for API responses
        self.api_patterns['successful_json_request'] = all_patterns['successful_json_request']
        self.api_patterns['failed_json_request'] = all_patterns['failed_json_request']
        
        # API structure for storing correlated API information
        self.api_structure = {}
    
    @property
    def plugin_type(self) -> str:
        """Get the plugin type."""
        return 'api_analyzer'
    
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
            '.json', '.js', '.py', '.java', '.php', '.ts', '.html', '.xml', 
            '.yaml', '.yml', '.md', '.txt', '.log'
        }
    
    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Analyze file content for API-related information.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Content of the file
            results: Existing results dictionary to update
            
        Returns:
            Updated results dictionary
        """
        logging.info(f"Analyzing API information in {file_path}")
        
        # Extract API structure and correlations
        self.extract_api_structure(content, results)
        
        # Detect API frameworks
        self.detect_api_frameworks(content, results)
        
        # Extract API responses
        self.extract_api_responses(content, results)
        
        # Extract complete API request examples
        self.extract_complete_api_requests(content, results)
        
        # Store API structure in the analyzer's state
        results['_api_structure'] = self.api_structure
        
        return results
    
    def extract_api_structure(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Extract and correlate API endpoints with their methods, parameters, and response types.
        
        Args:
            content: The file content to analyze
            results: Results dictionary to update
        """
        # Look for OpenAPI/Swagger schemas first
        openapi_match = re.search(r'(?i)"swagger"\s*:\s*"([^"]+)"|"openapi"\s*:\s*"([^"]+)"', content)
        if openapi_match:
            version = openapi_match.group(1) or openapi_match.group(2)
            results['openapi_schema'].add(f"OpenAPI/Swagger detected: {version}")
            logging.info(f"Detected OpenAPI/Swagger schema version {version}")
        
        # Extract API endpoints and correlate with methods
        endpoints = {}
        
        # Find all potential API endpoints
        endpoint_matches = re.finditer(self.api_patterns['api_endpoint'], content)
        for match in endpoint_matches:
            endpoint = match.group(0)
            
            # Try to find methods associated with this endpoint
            # Look at surrounding context (100 chars before and after)
            context_window = content[max(0, match.start() - 100):min(len(content), match.end() + 100)]
            
            # Look for HTTP methods near the endpoint
            method_matches = re.finditer(self.api_patterns['api_method'], context_window)
            methods = set(m.group(0).strip('"\'') for m in method_matches)
            
            # Look for parameters
            params = set()
            param_matches = re.finditer(self.api_patterns['api_parameter'], context_window)
            params.update(p.group(0) for p in param_matches)
            
            if 'path_parameter' in self.api_patterns:
                path_param_matches = re.finditer(self.api_patterns['path_parameter'], endpoint)
                params.update(p.group(0) for p in path_param_matches)
            
            # Look for content types
            content_types = set()
            if 'content_type' in self.api_patterns:
                content_type_matches = re.finditer(self.api_patterns['content_type'], context_window)
                content_types.update(ct.group(0) for ct in content_type_matches)
            
            # Store the correlated information
            if endpoint not in endpoints:
                endpoints[endpoint] = {
                    'methods': methods,
                    'parameters': params,
                    'content_types': content_types
                }
            else:
                endpoints[endpoint]['methods'].update(methods)
                endpoints[endpoint]['parameters'].update(params)
                endpoints[endpoint]['content_types'].update(content_types)
        
        # Store the API structure for later use
        self.api_structure = endpoints
    
    def detect_api_frameworks(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Detect common API frameworks and patterns.
        
        Args:
            content: The file content to analyze
            results: Results dictionary to update
        """
        frameworks = []
        
        # REST API detection
        if re.search(r'(?i)rest[ful]?[\s_-]?api', content):
            frameworks.append('REST API')
        
        # GraphQL detection
        if re.search(r'(?i)(?:graphql|query\s+\{|mutation\s+\{)', content):
            frameworks.append('GraphQL')
        
        # SOAP detection
        if re.search(r'(?i)(?:<soap:|<\/soap:|soap:Envelope)', content):
            frameworks.append('SOAP')
        
        # gRPC detection
        if re.search(r'(?i)(?:grpc\.|\bproto3\b)', content):
            frameworks.append('gRPC')
        
        # OpenAPI/Swagger detection
        if re.search(r'(?i)(?:"swagger":|"openapi":)', content):
            frameworks.append('OpenAPI/Swagger')
        
        # Store detected frameworks
        if frameworks:
            for framework in frameworks:
                results['api_framework'].add(framework)
                logging.info(f"Detected API framework: {framework}")
    
    def extract_api_responses(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Extract and categorize API responses by success/failure status.
        
        Args:
            content: The file content to analyze
            results: Results dictionary to update
        """
        # Find JSON success patterns
        success_matches = re.finditer(self.api_patterns['successful_json_request'], content)
        for match in success_matches:
            # Extract a reasonable chunk of the JSON response (not just the matching part)
            start_pos = match.start()
            
            # Try to find the end of this JSON object
            brace_count = 0
            end_pos = start_pos
            
            # Find opening brace
            while start_pos < len(content) and content[start_pos] != '{':
                start_pos += 1
            
            # Find matching closing brace
            for i in range(start_pos, min(start_pos + 500, len(content))):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            # Extract a reasonable sample of the JSON
            json_sample = content[start_pos:end_pos]
            if len(json_sample) > 200:
                json_sample = json_sample[:197] + "..."
            
            results['successful_json_request'].add(json_sample)
        
        # Find JSON error patterns
        error_matches = re.finditer(self.api_patterns['failed_json_request'], content)
        for match in error_matches:
            # Similar extraction logic as above
            start_pos = match.start()
            
            while start_pos < len(content) and content[start_pos] != '{':
                start_pos += 1
            
            brace_count = 0
            end_pos = start_pos
            
            for i in range(start_pos, min(start_pos + 500, len(content))):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            json_sample = content[start_pos:end_pos]
            if len(json_sample) > 200:
                json_sample = json_sample[:197] + "..."
            
            results['failed_json_request'].add(json_sample)
    
    def extract_complete_api_requests(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Extract complete API requests including method, endpoint, headers, and payload.
        
        Args:
            content: The file content to analyze
            results: Results dictionary to update
        """
        # Initialize request examples collection if it doesn't exist
        if 'api_request_examples' not in results:
            results['api_request_examples'] = set()
        
        # Look for patterns that might indicate complete API requests
        request_patterns = [
            # cURL command pattern
            r'(?i)curl\s+(?:-X\s+)?(?P<method>GET|POST|PUT|DELETE|PATCH)\s+["\']?(?P<url>https?://[^\s"\']+)["\']?(?P<options>(?:\s+-H\s+["\'][^"\']+["\']|\s+--header\s+["\'][^"\']+["\']|\s+-d\s+["\'].*?["\']|\s+--data\s+["\'].*?["\']|\s+--data-raw\s+["\'](.+?)["\']|\s+-F\s+["\'].*?["\'])*)',
            
            # JavaScript fetch/axios pattern
            r'(?i)(?:fetch|axios)(?:\.[a-zA-Z]+)?\(\s*["\'](?P<url>https?://[^\s"\']+)["\'](?:\s*,\s*\{(?P<options>.*?)\})?\s*\)',
            
            # Python requests pattern
            r'(?i)requests\.(?P<method>get|post|put|delete|patch)\(\s*["\'](?P<url>https?://[^\s"\']+)["\'](?:\s*,\s*(?P<options>.*?))?\s*\)',
            
            # Postman/insomnia-style documentation
            r'(?i)(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<url>https?://[^\s"\']+)[\s\n]+(?P<headers>(?:[A-Za-z0-9-]+:\s*[^\n]+[\n])+)(?:[\n\s]*(?P<body>\{.*?\}))?',
        ]
        
        # Define success indicators - patterns that suggest a request was successful
        success_indicators = [
            # HTTP success status codes
            r'(?i)(?:status(?:_code)?|code)\s*(?::|=|==)\s*(?:200|201|202|204|2\d{2})',
            # JSON success fields
            r'(?i)(?:"status"\s*:\s*(?:200|201|"success"|"ok"))',
            r'(?i)(?:"success"\s*:\s*(?:true|1))',
            r'(?i)(?:"ok"\s*:\s*(?:true|1))',
            # Success message patterns
            r'(?i)(?:"message"\s*:\s*"[^"]*(?:success|succeeded)[^"]*")',
            # Common success comments/logs
            r'(?i)(?:\/\/\s*success|#\s*success|console\.log\("[^"]*success[^"]*"\))',
            # Return data without errors
            r'(?i)(?:"data"\s*:\s*\{[^}]+\})(?![^}]*"error")',
            # Explicit validation of successful response
            r'(?i)(?:assert(?:Equal)?\([^)]*(?:200|201|(?:true|success))[^)]*\))',
        ]
        
        for pattern in request_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                try:
                    # First check if this request has evidence of success
                    # Examine context after the request (where the response would be)
                    context_window = content[match.start():min(len(content), match.end() + 500)]
                    success_found = False
                    
                    # Look for success indicators in the context window
                    for indicator in success_indicators:
                        if re.search(indicator, context_window):
                            success_found = True
                            break
                    
                    # Skip this request if no success indicators were found
                    if not success_found:
                        continue
                    
                    # Extract basic components
                    method = match.group('method').upper() if 'method' in match.groupdict() else "GET"
                    url = match.group('url')
                    
                    # Build request example
                    example = f"{method} {url}"
                    
                    # Process options/headers
                    if 'options' in match.groupdict() and match.group('options'):
                        options = match.group('options')
                        
                        # Extract headers
                        headers = []
                        header_matches = re.finditer(r'-H\s+["\']([^"\']+)["\']|--header\s+["\']([^"\']+)["\']', options)
                        for h_match in header_matches:
                            header = h_match.group(1) or h_match.group(2)
                            # Sanitize sensitive headers
                            if re.search(r'(?i)authorization|api[-_]?key|token|secret', header):
                                header = re.sub(r'(?i)(\b(?:authorization|api[-_]?key|token|secret)[^:]*:).*', r'\1 [REDACTED]', header)
                            headers.append(header)
                        
                        if headers:
                            example += "\nHeaders:"
                            for header in headers:
                                example += f"\n  {header}"
                        
                        # Extract body content if possible
                        body_match = re.search(r'-d\s+["\'](.+?)["\']|--data\s+["\'](.+?)["\']|--data-raw\s+["\'](.+?)["\']|body\s*:\s*(\{.+?\})|data\s*:\s*(\{.+?\})', options, re.DOTALL)
                        if body_match:
                            body = next((g for g in body_match.groups() if g), "")
                            if body:
                                # Truncate long bodies
                                if len(body) > 300:
                                    body = body[:297] + "..."
                                example += f"\nBody:\n  {body}"
                    
                    # For Postman/insomnia pattern
                    if 'headers' in match.groupdict() and match.group('headers'):
                        headers = match.group('headers').strip().split('\n')
                        example += "\nHeaders:"
                        for header in headers:
                            # Sanitize sensitive headers
                            if re.search(r'(?i)authorization|api[-_]?key|token|secret', header):
                                header = re.sub(r'(?i)(\b(?:authorization|api[-_]?key|token|secret)[^:]*:).*', r'\1 [REDACTED]', header)
                            if header.strip():
                                example += f"\n  {header.strip()}"
                    
                    if 'body' in match.groupdict() and match.group('body'):
                        body = match.group('body')
                        if len(body) > 300:
                            body = body[:297] + "..."
                        example += f"\nBody:\n  {body}"
                    
                    # Add explicit success note
                    example += "\nStatus: SUCCESSFUL REQUEST"
                    
                    # Store the example
                    results['api_request_examples'].add(example)
                    
                except Exception as e:
                    # Don't crash if something goes wrong with one example
                    logging.warning(f"Error processing API request example: {str(e)}")
    
    def get_api_structure(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the extracted API structure.
        
        Returns:
            API structure dictionary
        """
        return self.api_structure 