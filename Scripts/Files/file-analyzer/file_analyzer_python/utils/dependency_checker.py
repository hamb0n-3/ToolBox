#!/usr/bin/env python3
# Dependency checking utilities

import sys
import importlib
import platform
import subprocess
import shutil
import os
from typing import Dict, List, Tuple, Optional, Set
import logging

def check_dependencies(skip_checks: bool = False) -> bool:
    """
    Check if all required dependencies are installed.
    
    Args:
        skip_checks: Whether to skip dependency checks
        
    Returns:
        True if all dependencies are available or checks are skipped, False otherwise
    """
    if skip_checks:
        print("✅ Skipping dependency checks as requested.")
        return True
    
    # Setup colored output for better visibility
    colors = setup_colored_output()
    
    print(f"{colors['blue']('Checking dependencies...')}")
    
    # Dictionary of required modules and their pip install commands
    # Format: 'import_name': ('pip_package_name', is_required, minimum_version)
    required_modules = {
        # Core analysis modules (required)
        'sklearn': ('scikit-learn', True, '1.0.0'),
        'joblib': ('joblib', True, '1.1.0'),
        
        # Code analysis modules (required)
        'astroid': ('astroid', True, '2.11.0'),
        'radon': ('radon', True, '5.1.0'),
        
        # Binary analysis modules (required)
        'pefile': ('pefile', True, '2023.2.7'),
        'elftools': ('pyelftools', True, '0.29'),
        'macholib': ('macholib', True, '1.16'),
        
        # File type detection (required)
        'magic': ('python-magic' if platform.system() != 'Windows' else 'python-magic-bin', True, '0.4.27'),
        
        # Optional but recommended modules
        'colorama': ('colorama', False, '0.4.6'),    # For colored terminal output
        'tqdm': ('tqdm', False, '4.65.0'),           # For progress bars
        'numpy': ('numpy', False, '1.20.0'),         # For numerical operations
        'pandas': ('pandas', False, '1.3.0'),        # For data analysis
        'matplotlib': ('matplotlib', False, '3.5.0'), # For visualization
        'psutil': ('psutil', False, '5.9.0'),        # For system monitoring
    }
    
    # NLP module (optional but with additional steps)
    nlp_modules = {
        'spacy': ('spacy', False, '3.4.0')
    }
    
    # Check each module
    missing_required = []
    missing_optional = []
    outdated_modules = []
    
    for module_name, (pip_package, is_required, min_version) in required_modules.items():
        try:
            module = importlib.import_module(module_name)
            
            # Try to check version if the module has a __version__ attribute
            if hasattr(module, '__version__'):
                current_version = module.__version__
                if _version_is_lower(current_version, min_version):
                    outdated_modules.append((module_name, pip_package, current_version, min_version))
                    
        except ImportError:
            if is_required:
                missing_required.append((module_name, pip_package, min_version))
            else:
                missing_optional.append((module_name, pip_package, min_version))
    
    # Additional platform-specific dependencies for magic module
    if platform.system() == 'Windows' and 'magic' not in [m[0] for m in missing_required]:
        print(f"{colors['yellow']('Note:')} On Windows, additional DLL files might be needed for python-magic-bin to work.")
        print("These should be installed automatically with python-magic-bin.")
    elif platform.system() == 'Linux' and 'magic' not in [m[0] for m in missing_required]:
        # Check if libmagic is installed on Linux
        if not _check_libmagic():
            print(f"{colors['yellow']('Warning:')} libmagic might not be installed. Install it with your package manager:")
            print("  Debian/Ubuntu: sudo apt-get install libmagic1")
            print("  RHEL/CentOS/Fedora: sudo yum install file-libs")
    elif platform.system() == 'Darwin' and 'magic' not in [m[0] for m in missing_required]:
        # Check if libmagic is installed on macOS
        if not _check_libmagic():
            print(f"{colors['yellow']('Warning:')} libmagic might not be installed. Install it with Homebrew:")
            print("  brew install libmagic")
    
    # If any required modules are missing, show error
    if missing_required:
        print(f"\n{colors['red']('❌ ERROR: Missing required dependencies')}")
        print("=" * 50)
        print("The following dependencies are required and must be installed:")
        
        for module_name, pip_package, min_version in missing_required:
            print(f"  - {module_name} (install with: pip install {pip_package}>={min_version})")
        
        print("\nTo install all required dependencies at once, run:")
        pip_command = "pip install " + " ".join(f"{pkg}>={ver}" for _, pkg, ver in missing_required)
        print(f"  {pip_command}")
        
        print("\nExiting due to missing dependencies.")
        return False
    
    # If any modules are outdated, show warning
    if outdated_modules:
        print(f"\n{colors['yellow']('⚠️ WARNING: Outdated dependencies')}")
        print("=" * 50)
        print("The following dependencies are outdated and should be updated:")
        
        for module_name, pip_package, current_version, min_version in outdated_modules:
            print(f"  - {module_name} (current: {current_version}, recommended: {min_version})")
            print(f"    Update with: pip install --upgrade {pip_package}>={min_version}")
    
    # If any optional modules are missing, show recommendation
    if missing_optional:
        print(f"\n{colors['yellow']('⚠️ NOTE: Missing optional dependencies')}")
        print("=" * 50)
        print("The following dependencies are optional but recommended for full functionality:")
        
        for module_name, pip_package, min_version in missing_optional:
            print(f"  - {module_name} (install with: pip install {pip_package}>={min_version})")
        
        print("\nTo install all optional dependencies at once, run:")
        pip_command = "pip install " + " ".join(f"{pkg}>={ver}" for _, pkg, ver in missing_optional)
        print(f"  {pip_command}")
    
    # Check NLP modules separately
    for module_name, (pip_package, is_required, min_version) in nlp_modules.items():
        try:
            module = importlib.import_module(module_name)
            # If spaCy is installed, check for language model
            if module_name == 'spacy':
                try:
                    import spacy
                    spacy.load("en_core_web_sm")
                except OSError:
                    print(f"\n{colors['yellow']('⚠️ WARNING: Missing spaCy language model')}")
                    print("=" * 50)
                    print("The spaCy module is installed, but the language model is missing.")
                    print("Install it with: python -m spacy download en_core_web_sm")
                    print("Semantic analysis features will be limited without the language model.")
        except ImportError:
            print(f"\n{colors['yellow']('⚠️ Note: Optional NLP module not installed')}")
            print("=" * 50)
            print(f"The {module_name} module provides advanced text analysis capabilities.")
            print(f"Install with: pip install {pip_package}>={min_version}")
            print(f"After installing spaCy, download the language model with:")
            print("python -m spacy download en_core_web_sm")
            print("Semantic analysis features will be disabled without this module.")
    
    # If we get here, all required dependencies are installed
    print(f"\n{colors['green']('✅ All required dependencies are installed correctly.')}")
    return True

def _check_libmagic() -> bool:
    """Check if libmagic is installed on the system."""
    if platform.system() == 'Windows':
        return True  # Not applicable on Windows
    
    # Check for libmagic on Unix-like systems
    try:
        # Try to run file command which uses libmagic
        result = subprocess.run(['file', '--version'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               text=True)
        return result.returncode == 0
    except:
        # If the command fails, libmagic might not be installed
        return False

def _version_is_lower(current: str, minimum: str) -> bool:
    """
    Compare version strings to determine if current is lower than minimum.
    
    Args:
        current: Current version string
        minimum: Minimum required version string
        
    Returns:
        True if current version is lower than minimum, False otherwise
    """
    try:
        current_parts = [int(x) for x in current.split('.')]
        minimum_parts = [int(x) for x in minimum.split('.')]
        
        # Make both lists the same length
        while len(current_parts) < len(minimum_parts):
            current_parts.append(0)
        while len(minimum_parts) < len(current_parts):
            minimum_parts.append(0)
        
        # Compare version components
        for i in range(len(current_parts)):
            if current_parts[i] < minimum_parts[i]:
                return True
            elif current_parts[i] > minimum_parts[i]:
                return False
        
        # If we get here, versions are equal
        return False
    except (ValueError, AttributeError):
        # If we can't parse the version, assume it's acceptable
        return False

def generate_requirements_file(output_path: str = "requirements.txt") -> None:
    """
    Generate a requirements.txt file with all needed dependencies.
    
    Args:
        output_path: Path where the requirements file should be saved
    """
    # Setup colored output for better visibility
    colors = setup_colored_output()
    
    # Specify requirements with minimum versions
    requirements = [
        "# Core analysis dependencies",
        "scikit-learn>=1.0.0",
        "joblib>=1.1.0",
        "numpy>=1.20.0",
        "",
        "# Code analysis dependencies",
        "astroid>=2.11.0",
        "radon>=5.1.0",
        "",
        "# Binary analysis dependencies",
        "pefile>=2023.2.7",
        "pyelftools>=0.29",
        "macholib>=1.16",
    ]
    
    # Add magic package with platform-specific variant
    if platform.system() == 'Windows':
        requirements.append("python-magic-bin>=0.4.14  # Windows-specific")
    else:
        requirements.append("python-magic>=0.4.27  # Linux/macOS")
    
    # Add optional dependencies
    requirements.extend([
        "",
        "# UI and progress tracking",
        "colorama>=0.4.6",
        "tqdm>=4.65.0",
        "",
        "# Data analysis and visualization",
        "pandas>=1.3.0",
        "matplotlib>=3.5.0",
        "",
        "# System monitoring",
        "psutil>=5.9.0",
        "",
        "# NLP and machine learning",
        "spacy>=3.4.0"
    ])
    
    # Create directory if it doesn't exist
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    with open(output_path, "w") as f:
        f.write("# Requirements for file-analyzer\n")
        f.write("# Install with: pip install -r requirements.txt\n\n")
        for req in requirements:
            f.write(f"{req}\n")
        
        # Add note about spaCy model
        f.write("\n# After installing dependencies, run:\n")
        f.write("# python -m spacy download en_core_web_sm\n")
        
        # Add platform-specific notes
        if platform.system() == 'Linux':
            f.write("\n# On Linux, also install:\n")
            f.write("# Debian/Ubuntu: sudo apt-get install libmagic1\n")
            f.write("# RHEL/CentOS/Fedora: sudo yum install file-libs\n")
        elif platform.system() == 'Darwin':
            f.write("\n# On macOS, also install:\n")
            f.write("# brew install libmagic\n")
    
    print(f"{colors['green']('✅ Generated requirements file at')} {output_path}")
    print(f"{colors['blue']('Install all dependencies with:')} pip install -r {output_path}")
    print(f"{colors['blue']('Don\'t forget to also run:')} python -m spacy download en_core_web_sm")
    
    # Check for platform-specific requirements
    if platform.system() == 'Linux':
        print(f"\n{colors['yellow']('On Linux, also install libmagic:')}")
        print("  Debian/Ubuntu: sudo apt-get install libmagic1")
        print("  RHEL/CentOS/Fedora: sudo yum install file-libs")
    elif platform.system() == 'Darwin':
        print(f"\n{colors['yellow']('On macOS, also install libmagic:')}")
        print("  brew install libmagic")

def check_pip_installation() -> bool:
    """
    Check if pip is installed and accessible.
    
    Returns:
        True if pip is installed, False otherwise
    """
    try:
        # Check if pip is in PATH
        if shutil.which('pip') is not None:
            return True
        
        # If not, try python -m pip
        result = subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False

def get_installed_packages() -> Dict[str, str]:
    """
    Get a dictionary of installed packages and their versions.
    
    Returns:
        Dictionary of package names and versions
    """
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--format=json'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode == 0:
            import json
            packages = json.loads(result.stdout)
            return {pkg['name'].lower(): pkg['version'] for pkg in packages}
        return {}
    except:
        return {}

def setup_colored_output():
    """
    Set up colored terminal output for better readability.
    
    Returns:
        Dict of color functions or no-op functions if colorama is not available
    """
    try:
        from colorama import init, Fore, Style
        init()  # Initialize colorama
        
        # Define color functions
        def red(text): return f"{Fore.RED}{text}{Style.RESET_ALL}"
        def green(text): return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
        def yellow(text): return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
        def blue(text): return f"{Fore.BLUE}{text}{Style.RESET_ALL}"
        def magenta(text): return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
        def cyan(text): return f"{Fore.CYAN}{text}{Style.RESET_ALL}"
        def bold(text): return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"
        
        return {
            "red": red,
            "green": green,
            "yellow": yellow,
            "blue": blue, 
            "magenta": magenta,
            "cyan": cyan,
            "bold": bold
        }
    except ImportError:
        # Fallback if colorama is not available
        def no_color(text): return text
        return {
            "red": no_color,
            "green": no_color,
            "yellow": no_color,
            "blue": no_color,
            "magenta": no_color,
            "cyan": no_color,
            "bold": no_color
        } 