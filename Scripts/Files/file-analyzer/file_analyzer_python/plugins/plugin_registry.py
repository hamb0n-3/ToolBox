#!/usr/bin/env python3
# Plugin registry to manage analyzer plugins

import os
import logging
import importlib
import pkgutil
from typing import Dict, List, Type, Optional, Set
from pathlib import Path

from .base_plugin import AnalyzerPlugin


class PluginRegistry:
    """
    Registry for managing analyzer plugins.
    
    This class handles the loading, registration, and management of 
    all analysis plugins. It provides methods to discover, load, and 
    access plugins by type.
    """
    
    def __init__(self):
        """Initialize an empty plugin registry."""
        # Dictionary to store plugins by type
        self.plugins: Dict[str, List[AnalyzerPlugin]] = {}
        self._plugin_classes: Dict[str, Type[AnalyzerPlugin]] = {}
        
    def register_plugin(self, plugin_class: Type[AnalyzerPlugin], config: Optional[Dict] = None) -> None:
        """
        Register a plugin class with optional configuration.
        
        Args:
            plugin_class: The plugin class to register
            config: Optional configuration dictionary for the plugin
        """
        # Instantiate the plugin
        plugin = plugin_class(config)
        plugin_type = plugin.plugin_type
        
        # Ensure the plugin type exists in our dictionary
        if plugin_type not in self.plugins:
            self.plugins[plugin_type] = []
            
        # Add the plugin to the registry
        self.plugins[plugin_type].append(plugin)
        self._plugin_classes[plugin_class.__name__] = plugin_class
        
        logging.info(f"Registered {plugin_class.__name__} plugin")
        
    def get_plugins_by_type(self, plugin_type: str) -> List[AnalyzerPlugin]:
        """
        Get all plugins of a specific type.
        
        Args:
            plugin_type: Type of plugins to retrieve
            
        Returns:
            List of plugins of the specified type
        """
        return self.plugins.get(plugin_type, [])
    
    def get_plugins_for_file(self, file_path: Path, file_type: str, content: Optional[str] = None) -> List[AnalyzerPlugin]:
        """
        Get all plugins that can analyze the given file.
        
        Args:
            file_path: Path to the file
            file_type: Detected file type
            content: Optional content of the file if already loaded
            
        Returns:
            List of plugins that can analyze the file
        """
        applicable_plugins = []
        
        for plugin_list in self.plugins.values():
            for plugin in plugin_list:
                if plugin.can_analyze(file_path, file_type, content):
                    applicable_plugins.append(plugin)
                    
        return applicable_plugins
    
    def discover_plugins(self, plugin_package: str = 'file_analyzer.plugins') -> None:
        """
        Discover and register all available plugins from the specified package.
        
        Args:
            plugin_package: Package path to search for plugins
        """
        logging.info(f"Discovering plugins in {plugin_package}...")
        
        # Import the package
        package = importlib.import_module(plugin_package)
        
        # Get the file path of the package
        package_path = os.path.dirname(package.__file__)
        
        # Walk through all modules in the package
        for _, name, is_pkg in pkgutil.iter_modules([package_path]):
            if is_pkg:
                # If it's a package, recursively discover plugins
                self.discover_plugins(f"{plugin_package}.{name}")
            else:
                try:
                    # Import the module
                    module = importlib.import_module(f"{plugin_package}.{name}")
                    
                    # Inspect all attributes in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        
                        # Check if it's a class and a subclass of AnalyzerPlugin
                        if (isinstance(attr, type) and 
                            issubclass(attr, AnalyzerPlugin) and 
                            attr is not AnalyzerPlugin):
                            
                            # Register the plugin
                            self.register_plugin(attr)
                except Exception as e:
                    logging.error(f"Error loading plugin from {name}: {str(e)}")
                    
        logging.info(f"Discovered {sum(len(plugins) for plugins in self.plugins.values())} plugins")
    
    def get_supported_file_types(self) -> Set[str]:
        """
        Get a set of all file types supported by registered plugins.
        
        Returns:
            Set of supported file extensions or types
        """
        supported_types = set()
        
        for plugin_list in self.plugins.values():
            for plugin in plugin_list:
                supported_types.update(plugin.supported_file_types)
                
        return supported_types 