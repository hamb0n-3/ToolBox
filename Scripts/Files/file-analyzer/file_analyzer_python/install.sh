#!/bin/bash
# Install script for File Analyzer

echo "Installing File Analyzer..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment (optional)
if [[ "$1" == "--venv" ]]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    PIP="venv/bin/pip"
else
    PIP="pip3"
fi

# Install the package
echo "Installing package..."
$PIP install -e .[all]

# Try to install optional dependencies
echo "Installing optional dependencies..."
$PIP install -e ".[all]" || echo "Some optional dependencies could not be installed."

# Install language model for spaCy if spaCy is installed
if $PIP show spacy &> /dev/null; then
    echo "Installing spaCy language model..."
    python3 -m spacy download en_core_web_sm || echo "Could not install spaCy language model."
fi

echo "Installation complete!"
echo "You can now use the file-analyzer command:"
echo "file-analyzer path/to/file.py"

if [[ "$1" == "--venv" ]]; then
    echo ""
    echo "Note: The package was installed in a virtual environment."
    echo "To use it, you need to activate the environment first:"
    echo "source venv/bin/activate"
fi 