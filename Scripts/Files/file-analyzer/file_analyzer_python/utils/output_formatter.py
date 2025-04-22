#!/usr/bin/env python3
# Output formatting utilities

from typing import Dict, Set, Any, List, Optional, Tuple
import json
import os
import time
import datetime
from pathlib import Path

def format_results(results: Dict[str, Set[str]], api_structure: Optional[Dict] = None, 
                   markdown_format: bool = False, colors: Optional[Dict] = None) -> str:
    """
    Format analysis results for display.
    
    Args:
        results: Dictionary of result categories and their values
        api_structure: API structure correlation data (optional)
        markdown_format: Whether to format for markdown
        colors: Dictionary of color functions (optional)
        
    Returns:
        Formatted string of results
    """
    output = []
    
    # Use colors if provided, otherwise create no-op functions
    if colors is None:
        colors = {k: lambda x: x for k in ["red", "green", "yellow", "blue", "magenta", "cyan", "bold"]}
    
    # Start markdown output if requested
    if markdown_format:
        output.append("```")
    
    # Add timestamp and header
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output.append(f"{colors['bold']('=== File Analysis Results ===')}")
    output.append(f"{colors['blue']('Generated on:')} {current_time}\n")
    
    # Add file metadata if available
    if 'file_metadata' in results and results['file_metadata']:
        output.append(f"{colors['cyan']('File Metadata:')}")
        for metadata in sorted(results['file_metadata']):
            output.append(f"  {metadata}")
        output.append("")
    
    # Check for runtime errors
    if 'runtime_errors' in results and results['runtime_errors']:
        output.append(f"{colors['red']('Runtime Errors:')}")
        for error in sorted(results['runtime_errors']):
            output.append(f"  ! {error}")
        output.append("")
    
    # Define categories for better organization
    categories = {
        'Network Information': ['ipv4', 'ipv6', 'domain_keywords', 'url', 'mac_address'],
        'Authentication': ['username', 'password', 'jwt', 'access_token', 'refresh_token', 'oauth_token', 'api_token', 'auth_token'],
        'API & Keys': ['api_key', 'aws_key', 'api_key_param', 'cloud_key', 'firebase_key', 'service_account', 'client_id', 'client_secret'],
        'Cryptography': ['private_key', 'public_key', 'hash', 'encryption_key', 'certificate', 'signature'],
        'Sensitive Data': ['credit_card', 'social_security', 'email', 'phone_number', 'personal_id', 'passport_number'],
        'Session Management': ['session_id', 'cookie', 'csrf_token', 'nonce'],
        'Database': ['database_connection', 'sql_query', 'database_credential', 'connection_string', 'mongodb_uri'],
        'Encoded Data': ['base64_encoded', 'hex_encoded', 'url_encoded', 'compressed_data', 'serialized_data'],
        'API Information': [
            'api_endpoint', 'api_method', 'content_type', 'api_version', 
            'api_parameter', 'authorization_header', 'rate_limit', 
            'api_key_param', 'curl_command', 'webhook_url', 'http_status_code',
            'rest_resource', 'path_parameter', 'query_parameter', 
            'xml_response', 'request_header', 'request_body_json', 'form_data'
        ],
        'API Request Examples': ['api_request_examples'],
        'API Responses': ['successful_json_request', 'failed_json_request'],
        'API Frameworks': ['api_framework', 'openapi_schema', 'graphql_query', 'graphql_schema', 'soap_wsdl'],
        'API Security': ['api_auth_scheme', 'oauth_flow', 'api_security_header'],
        'API Error Handling': ['error_pattern', 'http_error', 'exception_handler'],
        'API Documentation': ['api_doc_comment', 'swagger_annotation', 'openapi_tag'],
        'API Advanced Features': ['webhook_event', 'pagination', 'rate_limit_header', 'caching_header'],
        'Code Quality': [
            'code_complexity', 'security_smells', 'code_quality', 
            'high_entropy_strings', 'commented_code', 'deprecated_api'
        ],
        'Network': [
            'network_protocols', 'network_security_issues', 'network_ports', 
            'network_hosts', 'network_endpoints', 'firewall_rule'
        ],
        'Software': ['software_versions', 'dependency', 'framework_version', 'os_specific_code'],
        'ML Detection': ['ml_credential_findings', 'ml_api_findings', 'ml_security_findings'],
    }

    # Count total findings
    total_findings = sum(len(values) for values in results.values() 
                        if isinstance(values, set) and values)
    
    output.append(f"{colors['green']('Total Findings:')} {total_findings}")
    
    # Add findings by category
    for category, data_types in categories.items():
        category_output = []
        category_findings = 0
        
        # Count findings in this category
        for data_type in data_types:
            if data_type in results and results[data_type]:
                category_findings += len(results[data_type])
        
        if category_findings == 0:
            continue
            
        category_output.append(f"\n{colors['cyan'](category)} ({category_findings} findings):")
        
        for data_type in data_types:
            if data_type in results and results[data_type]:
                values = results[data_type]
                category_output.append(f"  {colors['green'](data_type.replace('_', ' ').title())} ({len(values)} found):")
                
                # Sort values but prioritize shorter ones first (often more relevant)
                sorted_values = sorted(values, key=lambda x: (len(x), x))
                
                for value in sorted_values:
                    # Apply special formatting to different types of findings
                    if data_type in ['security_smells', 'network_security_issues', 'high_entropy_strings']:
                        category_output.append(f"    - {colors['yellow'](value)}")
                    elif data_type in ['api_key', 'password', 'private_key', 'credit_card', 'access_token']:
                        category_output.append(f"    - {colors['red'](value)}")
                    elif data_type in ['api_endpoint', 'url', 'api_method']:
                        category_output.append(f"    - {colors['blue'](value)}")
                    else:
                        category_output.append(f"    - {value}")
        
        # Only add the category if it has content
        if len(category_output) > 1:
            output.extend(category_output)

    # Print correlated API structure if available
    if api_structure and api_structure.items():
        output.append(f"\n{colors['cyan']('Correlated API Structure:')}")
        for endpoint, details in sorted(api_structure.items()):
            output.append(f"  {colors['magenta']('ENDPOINT:')} {endpoint}")
            
            if details.get('methods'):
                output.append(f"    {colors['blue']('Methods:')} {', '.join(details['methods'])}")
            
            if details.get('parameters'):
                output.append(f"    {colors['green']('Parameters:')} {', '.join(details['parameters'])}")
            
            if details.get('auth'):
                output.append(f"    {colors['yellow']('Auth:')} {details['auth']}")
                
            if details.get('content_types'):
                output.append(f"    {colors['blue']('Content Types:')} {', '.join(details['content_types'])}")
            
            output.append("")  # Empty line for readability
    
    # Add warning disclaimer
    output.append("\n" + "="*80)
    output.append(colors['yellow']("WARNING DISCLAIMER:"))
    output.append("-"*80)
    output.append("This analysis is based on pattern matching and heuristics, and may not be exhaustive.")
    output.append("Some API endpoints, credentials, or sensitive data might not be detected.")
    output.append("Successful API request examples are based on contextual clues and might be incomplete.")
    output.append("For critical security analysis, always perform manual verification.")
    output.append("="*80)
    
    # End markdown output if requested
    if markdown_format:
        output.append("```")
    
    return "\n".join(output)

def _get_severity_class(data_type: str) -> str:
    """
    Determine the severity class for a given data type.
    
    Args:
        data_type: The type of data
        
    Returns:
        CSS class name for the severity
    """
    high_severity = [
        'password', 'private_key', 'api_key', 'aws_key', 'credit_card', 
        'social_security', 'access_token', 'security_smells', 'network_security_issues'
    ]
    
    medium_severity = [
        'high_entropy_strings', 'jwt', 'oauth_token', 'session_id', 'username',
        'database_connection', 'http_error', 'code_quality'
    ]
    
    if data_type in high_severity:
        return "high-severity"
    elif data_type in medium_severity:
        return "medium-severity"
    else:
        return "normal"

def export_results_json(results: Dict[str, Set[str]], output_file: str) -> None:
    """
    Export analysis results to a JSON file.
    
    Args:
        results: Dictionary of result categories and their values
        output_file: Path to save the JSON file
    """
    # Convert sets to lists for JSON serialization
    json_results = {}
    
    # Add timestamp
    json_results["_metadata"] = {
        "timestamp": datetime.datetime.now().isoformat(),
        "generated_by": "file-analyzer",
        "version": "1.0.0"
    }
    
    for key, value in results.items():
        json_results[key] = sorted(list(value)) if isinstance(value, set) else value
    
    # Ensure directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(json_results, f, indent=2, sort_keys=True)
    
    print(f"Results exported to {output_file}")

def create_html_report(results: Dict[str, Set[str]], api_structure: Optional[Dict] = None, 
                      output_file: str = "file_analysis_report.html") -> None:
    """
    Create an HTML report from the analysis results.
    
    Args:
        results: Dictionary of result categories and their values
        api_structure: API structure correlation data (optional)
        output_file: Path to save the HTML report
    """
    # Define categories for better organization (same as in format_results)
    categories = {
        'Network Information': ['ipv4', 'ipv6', 'domain_keywords', 'url', 'mac_address'],
        'Authentication': ['username', 'password', 'jwt', 'access_token', 'refresh_token', 'oauth_token', 'api_token', 'auth_token'],
        'API & Keys': ['api_key', 'aws_key', 'api_key_param', 'cloud_key', 'firebase_key', 'service_account', 'client_id', 'client_secret'],
        'Cryptography': ['private_key', 'public_key', 'hash', 'encryption_key', 'certificate', 'signature'],
        'Sensitive Data': ['credit_card', 'social_security', 'email', 'phone_number', 'personal_id', 'passport_number'],
        'Session Management': ['session_id', 'cookie', 'csrf_token', 'nonce'],
        'Database': ['database_connection', 'sql_query', 'database_credential', 'connection_string', 'mongodb_uri'],
        'Encoded Data': ['base64_encoded', 'hex_encoded', 'url_encoded', 'compressed_data', 'serialized_data'],
        'API Information': [
            'api_endpoint', 'api_method', 'content_type', 'api_version', 
            'api_parameter', 'authorization_header', 'rate_limit', 
            'api_key_param', 'curl_command', 'webhook_url', 'http_status_code',
            'rest_resource', 'path_parameter', 'query_parameter', 
            'xml_response', 'request_header', 'request_body_json', 'form_data'
        ],
        'API Request Examples': ['api_request_examples'],
        'API Responses': ['successful_json_request', 'failed_json_request'],
        'API Frameworks': ['api_framework', 'openapi_schema', 'graphql_query', 'graphql_schema', 'soap_wsdl'],
        'API Security': ['api_auth_scheme', 'oauth_flow', 'api_security_header'],
        'API Error Handling': ['error_pattern', 'http_error', 'exception_handler'],
        'API Documentation': ['api_doc_comment', 'swagger_annotation', 'openapi_tag'],
        'API Advanced Features': ['webhook_event', 'pagination', 'rate_limit_header', 'caching_header'],
        'Code Quality': [
            'code_complexity', 'security_smells', 'code_quality', 
            'high_entropy_strings', 'commented_code', 'deprecated_api'
        ],
        'Network': [
            'network_protocols', 'network_security_issues', 'network_ports', 
            'network_hosts', 'network_endpoints', 'firewall_rule'
        ],
        'Software': ['software_versions', 'dependency', 'framework_version', 'os_specific_code'],
        'ML Detection': ['ml_credential_findings', 'ml_api_findings', 'ml_security_findings'],
        'Runtime': ['runtime_errors', 'file_metadata']
    }
    
    # Get file metadata
    file_metadata = {}
    if 'file_metadata' in results:
        for metadata in results['file_metadata']:
            if ':' in metadata:
                key, value = metadata.split(':', 1)
                file_metadata[key.strip()] = value.strip()
    
    # Count total findings
    total_findings = sum(len(values) for key, values in results.items() 
                        if isinstance(values, set) and key != 'file_metadata' and key != 'runtime_errors')
    
    # Start building HTML content
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Analysis Report</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { 
                font-family: 'Segoe UI', Arial, sans-serif; 
                margin: 0; 
                padding: 0;
                color: #333;
                background-color: #f8f9fa;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            header {
                background-color: #343a40;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 5px;
            }
            h1, h2, h3 { margin-top: 0; }
            .summary {
                background-color: white;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,.1);
                margin-bottom: 20px;
            }
            .metadata {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 10px;
            }
            .metadata-item {
                padding: 5px;
                border-bottom: 1px solid #eee;
            }
            .category { 
                background-color: white;
                margin-top: 20px; 
                border-radius: 5px;
                padding: 20px;
                box-shadow: 0 1px 3px rgba(0,0,0,.1);
            }
            .category h2 {
                border-bottom: 2px solid #007bff;
                padding-bottom: 10px;
                color: #007bff;
            }
            .datatype { 
                margin-left: 20px; 
                margin-top: 15px; 
                padding: 10px;
                background-color: #f8f9fa;
                border-radius: 4px;
            }
            .datatype h3 {
                margin: 0;
                font-size: 16px;
                color: #495057;
            }
            .values-container {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
                gap: 5px;
                margin-top: 10px;
            }
            .value { 
                margin-bottom: 5px; 
                padding: 8px;
                background-color: white;
                border-radius: 3px;
                border-left: 4px solid #6c757d;
                overflow-wrap: break-word;
                word-wrap: break-word;
                word-break: break-word;
            }
            .high-severity { 
                border-left-color: #dc3545;
                background-color: #fdf7f7;
            }
            .medium-severity {
                border-left-color: #ffc107;
                background-color: #fffdf7;
            }
            .api-endpoint {
                border-left-color: #17a2b8;
                background-color: #f0f9fa;
            }
            .runtime-error {
                background-color: #f8d7da;
                border-left-color: #dc3545;
                color: #721c24;
            }
            .endpoint { 
                background-color: #e9f5ff; 
                padding: 15px; 
                margin: 10px 0; 
                border-radius: 4px; 
                border-left: 4px solid #007bff;
            }
            .endpoint-method {
                background-color: #007bff;
                color: white;
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                margin-right: 10px;
                font-size: 12px;
            }
            .disclaimer { 
                background-color: #fff3cd; 
                padding: 15px; 
                border: 1px solid #ffeeba; 
                border-radius: 4px; 
                margin-top: 30px; 
                color: #856404;
            }
            .badge {
                display: inline-block;
                padding: 3px 7px;
                font-size: 12px;
                font-weight: 700;
                border-radius: 10px;
                margin-left: 5px;
            }
            .badge-primary { background-color: #007bff; color: white; }
            .badge-danger { background-color: #dc3545; color: white; }
            .badge-warning { background-color: #ffc107; color: #212529; }
            .collapsible {
                background-color: #f8f9fa;
                color: #444;
                cursor: pointer;
                padding: 18px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 15px;
                border-radius: 4px;
                margin-bottom: 5px;
                transition: 0.4s;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .active, .collapsible:hover { background-color: #e9ecef; }
            .collapsible:after { content: '\\002B'; font-weight: bold; float: right; }
            .active:after { content: '\\2212'; }
            .content {
                padding: 0 18px;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.2s ease-out;
                background-color: white;
                border-radius: 0 0 4px 4px;
            }
            .error-section {
                background-color: #f8d7da;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 20px;
            }
            @media (max-width: 768px) {
                .values-container {
                    grid-template-columns: 1fr;
                }
                .metadata {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>File Analysis Report</h1>
                <p>Generated on: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            </header>
    """
    
    # Add summary section
    html_content += """
        <section class="summary">
            <h2>Analysis Summary</h2>
            <p><strong>Total Findings:</strong> """ + str(total_findings) + """</p>
    """
    
    # Add file metadata if available
    if file_metadata:
        html_content += """
            <h3>File Metadata</h3>
            <div class="metadata">
        """
        
        for key, value in file_metadata.items():
            html_content += f'<div class="metadata-item"><strong>{key}:</strong> {value}</div>'
            
        html_content += """
            </div>
        """
    
    # Add runtime errors if any
    if 'runtime_errors' in results and results['runtime_errors']:
        html_content += """
            <div class="error-section">
                <h3>Runtime Errors</h3>
                <ul>
        """
        
        for error in sorted(results['runtime_errors']):
            html_content += f'<li>{error}</li>'
            
        html_content += """
                </ul>
            </div>
        """
        
    html_content += """
        </section>
    """
    
    # Add findings sections
    findings_added = False
    
    for category, data_types in categories.items():
        category_has_content = False
        category_findings = 0
        
        # Skip the Runtime category which we handled separately
        if category == 'Runtime':
            continue
            
        # Check if this category has any content
        for data_type in data_types:
            if data_type in results and results[data_type]:
                category_has_content = True
                category_findings += len(results[data_type])
                
        if not category_has_content:
            continue
            
        findings_added = True
        html_content += f'''
        <section class="category">
            <h2>{category} <span class="badge badge-primary">{category_findings}</span></h2>
        '''
        
        for data_type in data_types:
            if data_type in results and results[data_type]:
                values = results[data_type]
                severity_class = _get_severity_class(data_type)
                
                # Create a collapsible section for each data type
                html_content += f'''
                <button class="collapsible">
                    {data_type.replace('_', ' ').title()} 
                    <span class="badge badge-{'danger' if severity_class == 'high-severity' else 'warning' if severity_class == 'medium-severity' else 'primary'}">{len(values)}</span>
                </button>
                <div class="content">
                    <div class="datatype">
                        <div class="values-container">
                '''
                
                # Sort values but prioritize shorter ones first (often more relevant)
                sorted_values = sorted(values, key=lambda x: (len(x), x))
                
                for value in sorted_values:
                    # Apply special class based on data type
                    value_class = severity_class
                    if data_type in ['api_endpoint', 'url']:
                        value_class = "api-endpoint"
                    
                    html_content += f'<div class="value {value_class}">{value}</div>'
                
                html_content += '''
                        </div>
                    </div>
                </div>
                '''
        
        html_content += '''
        </section>
        '''
    
    # Add API structure section if available
    if api_structure and api_structure.items():
        html_content += '''
        <section class="category">
            <h2>Correlated API Structure</h2>
        '''
        
        for endpoint, details in sorted(api_structure.items()):
            html_content += f'''
            <div class="endpoint">
                <h3>{endpoint}</h3>
            '''
            
            if details.get('methods'):
                html_content += '<div>'
                for method in details['methods']:
                    html_content += f'<span class="endpoint-method">{method}</span>'
                html_content += '</div>'
            
            if details.get('parameters'):
                html_content += f'<p><strong>Parameters:</strong> {", ".join(details["parameters"])}</p>'
            
            if details.get('auth'):
                html_content += f'<p><strong>Auth:</strong> {details["auth"]}</p>'
                
            if details.get('content_types'):
                html_content += f'<p><strong>Content Types:</strong> {", ".join(details["content_types"])}</p>'
            
            html_content += '''
            </div>
            '''
            
        html_content += '''
        </section>
        '''
    
    # Add disclaimer and JavaScript
    html_content += '''
        <div class="disclaimer">
            <h3>Warning Disclaimer</h3>
            <p>This analysis is based on pattern matching and heuristics, and may not be exhaustive.</p>
            <p>Some API endpoints, credentials, or sensitive data might not be detected.</p>
            <p>Successful API request examples are based on contextual clues and might be incomplete.</p>
            <p>For critical security analysis, always perform manual verification.</p>
        </div>
        
        <script>
        document.addEventListener("DOMContentLoaded", function() {
            var coll = document.getElementsByClassName("collapsible");
            for (var i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    if (content.style.maxHeight) {
                        content.style.maxHeight = null;
                    } else {
                        content.style.maxHeight = content.scrollHeight + "px";
                    }
                });
            }
        });
        </script>
    </div>
    </body>
    </html>
    '''
    
    # If no findings were added, show a message
    if not findings_added:
        html_content = html_content.replace('<section class="summary">', 
        '''<section class="summary">
            <div class="error-section">
                <h3>No Findings</h3>
                <p>No significant findings were detected in the analyzed file.</p>
            </div>
        ''')
    
    # Ensure directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Write HTML to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML report created at {output_file}")

def create_csv_report(results: Dict[str, Set[str]], output_file: str = "file_analysis_report.csv") -> None:
    """
    Create a CSV report from the analysis results.
    
    Args:
        results: Dictionary of result categories and their values
        output_file: Path to save the CSV report
    """
    import csv
    
    # Ensure directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow(['Category', 'Type', 'Value', 'Severity'])
        
        # Write data
        for category, values in sorted(results.items()):
            if not isinstance(values, set) or not values:
                continue
                
            severity = "High" if category in [
                'password', 'private_key', 'api_key', 'aws_key', 'credit_card', 
                'security_smells', 'network_security_issues'
            ] else "Medium" if category in [
                'high_entropy_strings', 'jwt', 'oauth_token', 'session_id'
            ] else "Low"
            
            for value in sorted(values):
                writer.writerow([
                    category.replace('_', ' ').title(),
                    category,
                    value,
                    severity
                ])
    
    print(f"CSV report created at {output_file}") 