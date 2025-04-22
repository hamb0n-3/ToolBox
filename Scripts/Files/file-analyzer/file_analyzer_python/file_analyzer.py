#!/usr/bin/env python3
# Wrapper script for the file analyzer
# This script provides backward compatibility with the original monolithic implementation

import sys
import os
import logging
import argparse

# Try to import from the new modular structure
try:
    from file_analyzer.main import main
    
    if __name__ == "__main__":
        # Run the new main function
        main()
        
except ImportError:
    # If the modular version is not installed, give instructions
    print("The modular version of File Analyzer is not installed.")
    print("You should install the package from the current directory:")
    print("\npip install -e .")
    print("\nOr use the original monolithic script directly:")
    print("python original_file_analyzer.py <args>")
    sys.exit(1) 