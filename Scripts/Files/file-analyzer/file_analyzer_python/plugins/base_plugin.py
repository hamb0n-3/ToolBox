#!/usr/bin/env python3
# Base plugin interface that all analyzer plugins should implement

import abc
from typing import Dict, Any, Set, Optional
from pathlib import Path


class AnalyzerPlugin(abc.ABC):
    """
    Abstract base class for all analyzer plugins.
    
    This provides the interface that all analyzer plugins must implement.
    Plugins are responsible for examining content and detecting specific 
    patterns or characteristics.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the plugin with optional configuration.
        
        Args:
            config: Optional configuration dictionary for this plugin
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        
    @property
    @abc.abstractmethod
    def plugin_type(self) -> str:
        """
        Return the type of plugin, e.g., 'code_analyzer', 'binary_analyzer', etc.
        """
        pass
    
    @property
    @abc.abstractmethod
    def supported_file_types(self) -> Set[str]:
        """
        Return a set of file extensions or types this plugin can analyze.
        Use '*' for plugins that can analyze any file type.
        """
        pass
    
    @abc.abstractmethod
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
        pass
    
    @abc.abstractmethod
    def analyze(self, file_path: Path, file_type: str, content: str, results: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Analyze the file content and update the results dictionary.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Content of the file
            results: Existing results dictionary to update
            
        Returns:
            Updated results dictionary
        """
        pass 