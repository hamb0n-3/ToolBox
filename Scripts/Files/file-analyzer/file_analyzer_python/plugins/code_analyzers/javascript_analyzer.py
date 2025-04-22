#!/usr/bin/env python3
# JavaScript code analyzer plugin

import re
import json
import logging
from pathlib import Path
from typing import Dict, Set, Optional, List, Any
from collections import defaultdict
import os

from ...core.patterns import get_language_security_patterns, get_network_patterns
from ..base_plugin import AnalyzerPlugin

class JavaScriptCodeAnalyzer(AnalyzerPlugin):
    """
    Plugin for analyzing JavaScript code files.
    
    This plugin detects security issues, code smells, framework usages, and potential vulnerabilities 
    in JavaScript code using pattern matching and advanced heuristics.
    """
    
    def __init__(self, config=None):
        """
        Initialize the JavaScript code analyzer plugin.
        
        Args:
            config: Optional configuration for this plugin
        """
        super().__init__(config)
        
        # Get JavaScript-specific security patterns
        self.security_patterns = get_language_security_patterns().get('javascript', {})
        
        # Add additional JavaScript-specific security patterns
        self.additional_security_patterns = {
            'Dangerous Eval': r'(?:\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\)|\bsetInterval\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\))',
            'Prototype Pollution': r'(?:Object\.assign|Object\.prototype\.|__proto__|constructor\.prototype)',
            'DOM XSS': r'(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML|\.write\s*\(|\.writeln\s*\()',
            'Insecure Randomness': r'(?:Math\.random\s*\(\))',
            'JWT Verification': r'(?:\.verify\s*\(\s*token\s*,\s*[\'"`][^\'"]+[\'"`]\s*[,\)])',
            'Sensitive Info Exposure': r'(?:localStorage\.setItem\s*\(\s*[\'"`][^\'"]+[\'"`]\s*,\s*(?:password|token|key|secret))',
            'Client-Side Validation': r'(?:\.validate\s*\(\s*\)|\.isValid\s*\(\s*\))',
            'Insecure Hashing': r'(?:\bMD5\b|\bSHA1\b)',
            'Event Listeners on Window': r'(?:window\.addEventListener\s*\(\s*[\'"`]message[\'"`])',
            'PostMessage Vulnerability': r'(?:\.postMessage\s*\(\s*[^,]+,\s*[\'"]\*[\'"])',
            'CSRF Vulnerability': r'(?:withCredentials\s*:\s*true)',
            'Content Security Policy': r'(?:unsafe-eval|unsafe-inline)',
            'Hardcoded Credentials': r'(?:username\s*[:=]\s*[\'"`][^\'"]+[\'"`]|password\s*[:=]\s*[\'"`][^\'"]+[\'"`]|apiKey\s*[:=]\s*[\'"`][^\'"]+[\'"`])',
            'Unsanitized Inputs': r'(?:\.param\s*\(\s*[\'"`][^\'"]+[\'"`]\s*\)|req\.query|req\.body)',
            'Regex DOS': r'(?:[^\\][.+*]\{\d+,\}|\(\.\*\)\+)',
        }
        
        # Extend with additional patterns
        self.security_patterns.update(self.additional_security_patterns)
        
        # Framework detection patterns
        self.framework_patterns = {
            'React': r'(?:React\.|ReactDOM\.|import\s+React|from\s+[\'"]react[\'"]|extends\s+React\.Component)',
            'Angular': r'(?:@Component|@NgModule|@Injectable|angular\.module|import\s+{\s*[^}]*Component[^}]*\s*}\s+from\s+[\'"]@angular/core[\'"])',
            'Vue': r'(?:new\s+Vue|Vue\.component|createApp|import\s+Vue|from\s+[\'"]vue[\'"])',
            'jQuery': r'(?:\$\(|\jQuery\(|import\s+\$|from\s+[\'"]jquery[\'"])',
            'Express': r'(?:express\(\)|app\.get\s*\(|app\.post\s*\(|app\.use\s*\(|router\.get\s*\(|import\s+express|from\s+[\'"]express[\'"])',
            'Axios': r'(?:axios\.|axios\(|import\s+axios|from\s+[\'"]axios[\'"])',
            'Lodash': r'(?:_\.|import\s+_|from\s+[\'"]lodash[\'"])',
            'Moment': r'(?:moment\.|import\s+moment|from\s+[\'"]moment[\'"])',
            'D3': r'(?:d3\.|import\s+\*\s+as\s+d3|from\s+[\'"]d3[\'"])',
            'Ember': r'(?:Ember\.|import\s+Ember|from\s+[\'"]ember[\'"])',
            'Next.js': r'(?:import\s+\{\s*[^}]*useRouter[^}]*\s*\}\s+from\s+[\'"]next/router[\'"]|NextPage|GetStaticProps)',
            'Nuxt.js': r'(?:import\s+\{\s*[^}]*useNuxt[^}]*\s*\}\s+from\s+[\'"]nuxt[\'"])',
            'GraphQL': r'(?:gql`|ApolloClient|import\s+\{\s*[^}]*gql[^}]*\s*\}\s+from|useQuery\()',
            'Redux': r'(?:createStore|useSelector|useDispatch|import\s+\{\s*[^}]*createStore[^}]*\s*\}\s+from\s+[\'"]redux[\'"])',
            'Webpack': r'(?:webpack\.|module\.exports|import\s+webpack)',
            'Jest': r'(?:describe\(|it\(|test\(|expect\(|jest\.|import\s+\{\s*[^}]*(jest|expect)[^}]*\s*\}\s+from)',
            'Cypress': r'(?:cy\.|Cypress\.|describe\(.*cy\.)',
            'Firebase': r'(?:firebase\.|initializeApp\(|import\s+\{\s*[^}]*initializeApp[^}]*\s*\}\s+from\s+[\'"]firebase[\'"])',
            'TypeScript': r'(?:implements\s+|interface\s+[\w_]+\s*\{|type\s+[\w_]+\s*=|as\s+[\w_]+)',
        }
        
        # Network-related patterns
        self.network_patterns = get_network_patterns()
        
        # Code complexity patterns
        self.complexity_patterns = {
            'complex_function': r'function\s+[\w_]+\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}',
            'nested_callbacks': r'\.then\s*\(\s*(?:function|\([^)]*\)\s*=>).*\.then\s*\(\s*(?:function|\([^)]*\)\s*=>)',
            'deep_nesting': r'(?:\{[^{}]*){5,}',
            'long_line': r'.{120,}',
            'large_object': r'(?:\{[^\}]*(?:(?:\{[^\}]*\})[^\}]*){5,})',
            'multiple_returns': r'(?:return[^;]*;.*){4,}',
            'large_array': r'(?:\[[^\]]*(?:(?:\[[^\]]*\])[^\]]*){5,})',
            'many_parameters': r'function\s+[\w_]+\s*\([^)]{80,}\)',
            'complex_regex': r'\/(?:\\.|[^\/]){40,}\/',
            'complex_ternary': r'\?[^:?]*(?:\?[^:?]*:[^:?]*)+:',
        }
        
        # Initialize complexity thresholds
        self.complexity_thresholds = {
            'max_function_length': self.config.get('max_function_length', 100),
            'max_nesting_depth': self.config.get('max_nesting_depth', 4),
            'max_file_size': self.config.get('max_file_size', 1000),
            'max_line_length': self.config.get('max_line_length', 120),
            'max_params': self.config.get('max_params', 5),
        }
    
    @property
    def plugin_type(self) -> str:
        """Get the plugin type."""
        return 'code_analyzer'
    
    @property
    def supported_file_types(self) -> Set[str]:
        """Get supported file extensions."""
        return {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
    
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
        # Check file extension
        if file_path.suffix.lower() in self.supported_file_types:
            return True
        
        # If content is provided and no file extension, check for JavaScript signatures
        if content and file_path.suffix.lower() not in self.supported_file_types:
            js_signatures = [
                'function ', 'var ', 'let ', 'const ', 'import ', 'export ', 
                'class ', '() =>', 'window.', 'document.', 'module.exports', 
                'require(', 'async function', 'new Promise'
            ]
            
            # Check for typical JavaScript signatures
            for sig in js_signatures:
                if sig in content:
                    return True
        
        return False
    
    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Analyze JavaScript code for security issues, frameworks used, and complexity.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Content of the file
            results: Existing results dictionary to update
            
        Returns:
            Updated results dictionary
        """
        logging.info(f"Analyzing JavaScript code in {file_path}")
        
        try:
            # Security smell detection using patterns
            self._check_security_patterns(content, results)
            
            # Framework detection
            self._detect_frameworks(content, results)
            
            # Commented code detection
            self._detect_commented_code(content, results)
            
            # Code complexity analysis
            self._analyze_code_complexity(content, results)
            
            # API usage detection
            self._detect_api_usage(content, results)
            
            # Network functionality detection
            self._detect_network_features(content, results)
            
            # Package analysis if it's a package.json file
            if file_path.name == 'package.json':
                self._analyze_package_json(content, results)
            
            return results
            
        except Exception as e:
            logging.error(f"Error analyzing JavaScript code: {str(e)}")
            results['code_quality'].add(f"Error analyzing file: {str(e)}")
            return results
    
    def _check_security_patterns(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Check content for known security smells using regex patterns.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        for smell_name, pattern in self.security_patterns.items():
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = self._get_context(content, match.start(), 20)
                finding = f"{smell_name} (line {line_no}): {context.strip()}"
                results['security_smells'].add(finding)
    
    def _detect_frameworks(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Detect JavaScript frameworks and libraries used in the code.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        for framework, pattern in self.framework_patterns.items():
            if re.search(pattern, content, re.MULTILINE):
                results['api_framework'].add(f"JavaScript framework: {framework}")
    
    def _detect_commented_code(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Detect commented code in JavaScript files.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Match single-line comments with code-like content
        single_line_pattern = r'\/\/.*(?:function|var|let|const|if|for|while|switch|return|=|\{|\})'
        multi_line_pattern = r'\/\*[\s\S]*?(?:function|var|let|const|if|for|while|switch|return|=|\{|\})[\s\S]*?\*\/'
        
        # Check for commented code
        for pattern in [single_line_pattern, multi_line_pattern]:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                comment = match.group(0)
                # Skip if it's a documentation comment
                if '/**' in comment and '*/' in comment and ('@param' in comment or '@return' in comment):
                    continue
                results['commented_code'].add(f"Commented code at line {line_no}")
    
    def _analyze_code_complexity(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Analyze code complexity in JavaScript files.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Check for complex patterns
        for complexity_type, pattern in self.complexity_patterns.items():
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                
                if complexity_type == 'complex_function':
                    function_code = match.group(0)
                    lines = function_code.count('\n') + 1
                    if lines > self.complexity_thresholds['max_function_length']:
                        results['code_complexity'].add(f"Long function with {lines} lines at line {line_no}")
                
                elif complexity_type == 'nested_callbacks':
                    results['code_complexity'].add(f"Nested callbacks (promise chain) at line {line_no}")
                
                elif complexity_type == 'deep_nesting':
                    results['code_complexity'].add(f"Deep nesting detected at line {line_no}")
                
                elif complexity_type == 'long_line':
                    results['code_complexity'].add(f"Long line ({len(match.group(0))} chars) at line {line_no}")
                
                elif complexity_type == 'large_object':
                    results['code_complexity'].add(f"Complex object literal at line {line_no}")
                
                elif complexity_type == 'multiple_returns':
                    results['code_complexity'].add(f"Multiple return statements in function at line {line_no}")
                
                elif complexity_type == 'many_parameters':
                    params = match.group(0)
                    param_count = params.count(',') + 1
                    if param_count > self.complexity_thresholds['max_params']:
                        results['code_complexity'].add(f"Function with {param_count} parameters at line {line_no}")
                
                elif complexity_type == 'complex_regex':
                    results['code_complexity'].add(f"Complex regex pattern at line {line_no}")
                
                elif complexity_type == 'complex_ternary':
                    results['code_complexity'].add(f"Complex nested ternary expression at line {line_no}")
        
        # Additional complexity metrics
        
        # Check cyclomatic complexity by counting decision points
        decision_points = len(re.findall(r'\b(?:if|else|for|while|do|switch|case|catch|?)\b', content))
        if decision_points > 50:  # Arbitrary threshold for file level
            results['code_complexity'].add(f"High cyclomatic complexity with {decision_points} decision points")
        
        # Check file length
        lines = content.count('\n') + 1
        if lines > self.complexity_thresholds['max_file_size']:
            results['code_complexity'].add(f"Very large file with {lines} lines")
    
    def _detect_api_usage(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Detect API endpoints and usage patterns in JavaScript code.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Common HTTP client patterns
        http_patterns = {
            'Fetch API': r'fetch\s*\(\s*[\'"`](?P<url>[^\'"`]+)[\'"`]',
            'Axios GET': r'axios\.get\s*\(\s*[\'"`](?P<url>[^\'"`]+)[\'"`]',
            'Axios POST': r'axios\.post\s*\(\s*[\'"`](?P<url>[^\'"`]+)[\'"`]',
            'Axios Request': r'axios\s*\(\s*\{[^}]*url\s*:\s*[\'"`](?P<url>[^\'"`]+)[\'"`]',
            'jQuery AJAX': r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"`](?P<url>[^\'"`]+)[\'"`]',
            'XMLHttpRequest': r'\.open\s*\(\s*[\'"`](?:GET|POST|PUT|DELETE)[\'"`]\s*,\s*[\'"`](?P<url>[^\'"`]+)[\'"`]',
        }
        
        # Extract API endpoints from HTTP client calls
        for client, pattern in http_patterns.items():
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                url = match.group('url') if 'url' in match.groupdict() else "unknown"
                
                # Skip relative URLs without domains
                if not re.match(r'^https?://', url) and not url.startswith('/api/'):
                    continue
                    
                results['api_endpoint'].add(f"API endpoint ({client}): {url}")
    
    def _detect_network_features(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Detect network protocols and security issues.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        # Check for network protocols
        for protocol, pattern in self.network_patterns['protocols'].items():
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                results['network_protocols'].add(f"Network protocol: {protocol}")
        
        # Check for network security issues
        for issue, pattern in self.network_patterns['security_issues'].items():
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                context = self._get_context(content, match.start(), 20)
                results['network_security_issues'].add(f"{issue} at line {line_no}: {context.strip()}")
    
    def _analyze_package_json(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Analyze package.json for dependencies and potential issues.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        try:
            package_data = json.loads(content)
            
            # Extract dependencies
            dependencies = {}
            if 'dependencies' in package_data:
                dependencies.update(package_data['dependencies'])
            if 'devDependencies' in package_data:
                dependencies.update(package_data['devDependencies'])
            
            # Add to results
            for package, version in dependencies.items():
                results['dependency'].add(f"JavaScript package: {package} ({version})")
                
                # Check for security vulnerabilities in dependencies
                if (version.startswith('^0.') or version.startswith('~0.')
                    or version == '*' or version.startswith('>=') or version.startswith('>')):
                    results['security_smells'].add(f"Potentially insecure dependency version: {package} {version}")
            
            # Extract other metadata
            if 'name' in package_data:
                results['software_versions'].add(f"Package name: {package_data['name']}")
            if 'version' in package_data:
                results['software_versions'].add(f"Package version: {package_data['version']}")
            if 'license' in package_data:
                results['software_versions'].add(f"Package license: {package_data['license']}")
            
        except json.JSONDecodeError:
            results['code_quality'].add("Invalid JSON in package.json file")
        except Exception as e:
            logging.error(f"Error analyzing package.json: {str(e)}")
    
    def _get_context(self, content: str, position: int, context_size: int = 20) -> str:
        """
        Get context around a specific position in the content.
        
        Args:
            content: The content to extract context from
            position: Position in the content
            context_size: Number of characters before and after
            
        Returns:
            Context string
        """
        start = max(0, position - context_size)
        end = min(len(content), position + context_size)
        
        # Find the start of the line
        line_start = content.rfind('\n', 0, position)
        if line_start == -1:
            line_start = 0
        else:
            line_start += 1  # Skip the newline
            
        # Find the end of the line
        line_end = content.find('\n', position)
        if line_end == -1:
            line_end = len(content)
            
        # Return the full line with highlight
        return content[line_start:line_end].strip() 