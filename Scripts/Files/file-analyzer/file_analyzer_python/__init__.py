#!/usr/bin/env python3
"""
File Analyzer - A comprehensive file analysis tool for cybersecurity

This module provides tools for analyzing files to extract information
relevant for cybersecurity analysis, such as API endpoints, credentials,
security issues, and more.
"""

__version__ = "1.0.0"
__author__ = "Tristan Pereira"

from .core.analyzer import FileAnalyzer
from .main import main

__all__ = ['FileAnalyzer', 'main']
