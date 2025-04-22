# File Analyzer

A comprehensive file analysis tool for cybersecurity with a plugin-based architecture. This tool scans files to detect security issues, extract API endpoints, identify sensitive information, and more.

## Features

- **Plugin-Based Architecture**: Easily extend functionality by adding new plugins
- **Comprehensive Detection**: Identifies APIs, credentials, security issues, and more
- **Language-Specific Analysis**: Specialized analysis for Python, JavaScript, Java, and more
- **API Structure Extraction**: Correlates API endpoints with methods, parameters, and responses
- **Security-Focused**: Detects secrets, hardcoded credentials, and security vulnerabilities
- **Multiple Output Formats**: Console, markdown, JSON, and HTML reports

## Installation

### Basic Installation

```bash
pip install file-analyzer
```

### Installation with Extras

For specific functionality, you can install extras:

```bash
# For code analysis features
pip install "file-analyzer[code_analysis]"

# For machine learning features
pip install "file-analyzer[ml]"

# For binary analysis features
pip install "file-analyzer[binary]"

# For NLP-based analysis
pip install "file-analyzer[nlp]"

# For all features
pip install "file-analyzer[all]"
```

### Development Installation

```bash
git clone https://github.com/yourusername/file-analyzer.git
cd file-analyzer
pip install -e ".[all]"
```

## Usage

### Basic Usage

```bash
# Analyze a file
file-analyzer path/to/file.py

# Analyze a file and output in markdown format
file-analyzer path/to/file.py --md

# Export results to JSON
file-analyzer path/to/file.py --json results.json

# Generate an HTML report
file-analyzer path/to/file.py --html report.html
```

### Advanced Options

```bash
# Specify additional plugin directory
file-analyzer path/to/file.py --plugin-dir /path/to/plugins

# Set logging level
file-analyzer path/to/file.py --log-level DEBUG

# Skip dependency checks
file-analyzer path/to/file.py --skip-checks

# Use a configuration file
file-analyzer path/to/file.py --config config.json
```

## Creating Custom Plugins

You can extend functionality by creating custom plugins:

1. Create a new Python file in the `plugins` directory
2. Create a class that inherits from `AnalyzerPlugin`
3. Implement the required methods
4. The plugin will be automatically discovered and loaded

Example plugin:

```python
from file_analyzer.plugins.base_plugin import AnalyzerPlugin

class MyCustomPlugin(AnalyzerPlugin):
    @property
    def plugin_type(self):
        return 'custom_analyzer'
        
    @property
    def supported_file_types(self):
        return {'.custom', '.ext'}
        
    def can_analyze(self, file_path, file_type, content=None):
        return file_path.suffix in self.supported_file_types
        
    def analyze(self, file_path, file_type, content, results):
        # Analyze content and update results
        results['custom_findings'] = set(['Finding 1', 'Finding 2'])
        return results
```

## Configuration

You can create a configuration file to customize behavior:

```json
{
    "log_level": "INFO",
    "log_file": "file_analyzer.log",
    "plugin_dirs": [
        "/path/to/custom/plugins"
    ],
    "analysis_settings": {
        "max_entropy_threshold": 5.0,
        "code_complexity_threshold": 15
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 