#!/usr/bin/env python3
# Python code analyzer plugin

import re
import logging
import ast
from pathlib import Path
from typing import Dict, Set, Optional

from ...core.patterns import get_language_security_patterns
from ..base_plugin import AnalyzerPlugin

class PythonCodeAnalyzer(AnalyzerPlugin):
    """
    Plugin for analyzing Python code files.
    
    This plugin detects security issues, code smells, and complexity issues
    in Python code using both pattern matching and AST analysis.
    """
    
    def __init__(self, config=None):
        """Initialize the Python code analyzer plugin."""
        super().__init__(config)
        
        # Get Python-specific security patterns
        self.security_patterns = get_language_security_patterns().get('python', {})
    
    @property
    def plugin_type(self) -> str:
        """Get the plugin type."""
        return 'code_analyzer'
    
    @property
    def supported_file_types(self) -> Set[str]:
        """Get supported file extensions."""
        return {'.py', '.pyw'}
    
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
        return file_path.suffix.lower() in {'.py', '.pyw'} or file_type == 'text'
    
    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Analyze Python code for security issues and complexity.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Content of the file
            results: Existing results dictionary to update
            
        Returns:
            Updated results dictionary
        """
        logging.info(f"Analyzing Python code in {file_path}")
        
        try:
            # Parse the code
            tree = ast.parse(content)
            
            # Security smell detection using patterns
            self._check_security_patterns(content, results)
            
            # Complexity analysis using radon if available
            self._check_code_complexity(content, results)
            
            # AST-based security analysis
            self._analyze_ast_security(tree, content, results)
            
            return results
            
        except SyntaxError as e:
            line_no = getattr(e, 'lineno', '?')
            results['code_quality'].add(f"Python syntax error at line {line_no}: {str(e)}")
            logging.warning(f"Syntax error in {file_path}: {str(e)}")
            return results
        except Exception as e:
            logging.error(f"Error analyzing Python code: {str(e)}")
            return results
    
    def _check_security_patterns(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Check content for known security smells using regex patterns.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        for smell_name, pattern in self.security_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                # Extract surrounding context (20 chars before and after)
                context = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                # Format the finding
                finding = f"{smell_name} (line {line_no}): {context.strip()}"
                results['security_smells'].add(finding)
    
    def _check_code_complexity(self, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Check code complexity using radon if available.
        
        Args:
            content: The content to analyze
            results: Results dictionary to update
        """
        try:
            # Try to import radon
            from radon.complexity import cc_visit
            from radon.metrics import h_visit
            
            # Calculate cyclomatic complexity
            complexities = cc_visit(content)
            for item in complexities:
                if item.complexity > 10:  # Threshold for high complexity
                    results['code_complexity'].add(
                        f"High complexity ({item.complexity}) in {item.name} at line {item.lineno}"
                    )
            
            # Calculate maintainability index
            h_visit_result = h_visit(content)
            if h_visit_result.mi < 65:  # Low maintainability threshold
                results['code_quality'].add(
                    f"Low maintainability index: {h_visit_result.mi:.2f}/100"
                )
        except ImportError:
            logging.info("Radon not available, skipping complexity analysis")
        except Exception as e:
            logging.warning(f"Error calculating code metrics: {str(e)}")
    
    def _analyze_ast_security(self, tree: ast.AST, content: str, results: Dict[str, Set[str]]) -> None:
        """
        Analyze Python code using AST for security vulnerabilities.
        
        Args:
            tree: AST parse tree of the code
            content: Raw content of the file
            results: Results dictionary to update
        """
        # Use a visitor pattern to traverse the AST
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, file_content, results_dict):
                self.file_content = file_content
                self.results = results_dict
                
            def visit_Import(self, node):
                """Check for dangerous imports."""
                dangerous_modules = ['pickle', 'marshal', 'shelve', 'dill']
                for name in node.names:
                    if name.name in dangerous_modules:
                        self.results['security_smells'].add(
                            f"Dangerous module import: {name.name} (line {node.lineno})"
                        )
                self.generic_visit(node)
                
            def visit_Call(self, node):
                """Check for dangerous function calls."""
                if isinstance(node.func, ast.Name):
                    # Check for eval/exec
                    if node.func.id in ['eval', 'exec']:
                        self.results['security_smells'].add(
                            f"Dangerous function call: {node.func.id} (line {node.lineno})"
                        )
                    
                    # Check for file operations
                    if node.func.id == 'open':
                        # Look for file paths with sensitive keywords
                        if len(node.args) > 0 and isinstance(node.args[0], ast.Str):
                            path = node.args[0].s
                            if any(keyword in path.lower() for keyword in 
                                  ['secret', 'password', 'key', 'credential', 'token']):
                                self.results['security_smells'].add(
                                    f"Sensitive file operation: open('{path}') at line {node.lineno}"
                                )
                            
                            # Check for world-writable files
                            if len(node.args) > 1 and isinstance(node.args[1], ast.Str):
                                mode = node.args[1].s
                                if 'w' in mode:
                                    # Check for absolute paths that might be world-writable
                                    if path.startswith('/'):
                                        self.results['security_smells'].add(
                                            f"Potentially insecure file write: open('{path}', '{mode}') at line {node.lineno}"
                                        )
                
                # Check for subprocess calls with shell=True
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                                self.results['security_smells'].add(
                                    f"Shell injection risk: subprocess call with shell=True at line {node.lineno}"
                                )
                
                self.generic_visit(node)
                
            def visit_BinOp(self, node):
                """Check for string formatting vulnerabilities."""
                line_content = self.file_content.split('\n')[node.lineno-1] if node.lineno <= len(self.file_content.split('\n')) else ""
                
                # Check for SQL string formatting with %
                if isinstance(node.op, ast.Mod) and any(s in line_content.upper() for s in 
                                                      ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'EXEC']):
                    self.results['security_smells'].add(
                        f"Potential SQL injection with string formatting (line {node.lineno}): {line_content.strip()}"
                    )
                
                # Check for command injection with string concatenation
                if isinstance(node.op, ast.Add) and any(s in line_content.lower() for s in 
                                                     ['os.system', 'subprocess', 'popen', 'exec']):
                    self.results['security_smells'].add(
                        f"Potential command injection with string concatenation (line {node.lineno}): {line_content.strip()}"
                    )
                    
                self.generic_visit(node)
                
            def visit_Assign(self, node):
                """Check for hardcoded credentials and sensitive data."""
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(keyword in var_name for keyword in 
                              ['password', 'secret', 'key', 'token', 'apikey']):
                            # If variable name is sensitive, check if value is hardcoded
                            if isinstance(node.value, ast.Str):
                                if len(node.value.s) > 3:  # Only flag non-trivial values
                                    self.results['security_smells'].add(
                                        f"Hardcoded sensitive value in variable '{target.id}' at line {node.lineno}"
                                    )
                
                self.generic_visit(node)
                
            def visit_FunctionDef(self, node):
                """Check for dangerous function parameter patterns."""
                # Check for dangerous parameter names
                for arg in node.args.args:
                    if hasattr(arg, 'arg') and arg.arg.lower() in ['password', 'secret', 'token', 'key']:
                        # Function with sensitive parameter but no type annotation
                        if not hasattr(arg, 'annotation') or arg.annotation is None:
                            self.results['security_smells'].add(
                                f"Function '{node.name}' receives sensitive parameter '{arg.arg}' without type annotation at line {node.lineno}"
                            )
                
                self.generic_visit(node)
        
        # Apply the visitor
        visitor = SecurityVisitor(content, results)
        visitor.visit(tree) 