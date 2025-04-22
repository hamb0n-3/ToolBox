#!/usr/bin/env python3
# File handling utilities

import logging
import json
from pathlib import Path
from typing import Tuple, Optional

def read_file_content(file_path: Path) -> Tuple[str, bool]:
    """
    Read the content of a file with proper error handling.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Tuple of (file_content, is_binary)
    """
    is_binary = False
    
    try:
        # Try reading as text first
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Special handling for JSON files
        if file_path.suffix.lower() == '.json':
            try:
                # Try to parse as JSON
                json_content = json.loads(content)
                content = json.dumps(json_content)
            except json.JSONDecodeError as json_err:
                logging.warning(f"File {file_path} has invalid JSON syntax at {json_err}. Processing as text.")
    
    except UnicodeDecodeError:
        # If we hit decoding errors, it might be binary
        is_binary = True
        with open(file_path, 'rb') as f:
            content = f.read().hex()
            
    return content, is_binary

def detect_file_type(file_path: Path) -> str:
    """
    Detect file type using magic numbers and file extensions.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Detected file type as a string
    """
    try:
        import magic
        file_type = magic.from_file(str(file_path))
        
        # Categorize the file type
        if "PE32" in file_type or "PE32+" in file_type:
            return "executable"
        elif "ELF" in file_type:
            return "executable"
        elif "Mach-O" in file_type:
            return "executable"
        elif any(x in file_type for x in ["text", "JSON", "XML", "ASCII"]):
            return "text"
        elif "data" in file_type or "binary" in file_type:
            return "binary"
        else:
            return file_type
    except ImportError:
        # Fallback to extension-based detection
        suffix = file_path.suffix.lower()
        if suffix in ['.exe', '.dll', '.sys', '.so', '.dylib']:
            return "executable"
        elif suffix in ['.txt', '.json', '.xml', '.html', '.js', '.py', '.java', '.c', '.cpp']:
            return "text"
        else:
            return "unknown"

def calculate_entropy(string: str) -> float:
    """
    Calculate Shannon entropy of a string to help identify randomness.
    Higher entropy suggests more randomness, which is typical of hashes.
    
    Args:
        string: The string to analyze
        
    Returns:
        The calculated entropy value
    """
    import math
    
    if not string:
        return 0.0
        
    # Handle both string and bytes input
    if isinstance(string, bytes):
        string = string.decode('utf-8', errors='ignore')
        
    freq_dict = {}
    for c in string:
        freq_dict[c] = freq_dict.get(c, 0) + 1
        
    length = len(string)
    entropy = 0
    
    for freq in freq_dict.values():
        probability = freq / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def is_valid_base64(string: str) -> bool:
    """
    Validate if a string is valid base64 encoded.
    
    Args:
        string: String to check
        
    Returns:
        True if valid base64, False otherwise
    """
    import base64
    
    try:
        # Add padding if necessary
        padding = 4 - (len(string) % 4)
        if padding != 4:
            string += '=' * padding
        # Try to decode
        base64.b64decode(string)
        return True
    except Exception:
        return False 