# File Analyzer - Rust Implementation

This is a Rust rewrite of the original Python-based file analyzer tool. The Rust version offers improved performance, memory safety, and concurrency through Rust's strong guarantees.

## Overview

File Analyzer is a powerful command-line tool designed to identify security-relevant information in files, including:

- API endpoints and authentication details
- Network information (IPs, domains, URLs)
- Sensitive data (credentials, tokens, keys)
- High-entropy strings that may be secrets
- Code quality and security issues
- And much more!

## Features

- **Memory Safety**: Takes full advantage of Rust's memory safety guarantees
- **Thread Safety**: Uses Rayon for safe parallel processing of files
- **Performance**: Significantly faster analysis, especially for large files
- **Resource Efficiency**: Efficient memory management and streaming capabilities
- **Pattern Detection**: Uses the same comprehensive regex patterns from the original
- **Multiple Output Formats**: Console, JSON, HTML, and CSV output

## Key Benefits Over Python Version

1. **Performance**: Much faster processing, especially for large files
2. **Safety**: Memory safety and thread safety guaranteed at compile time
3. **Resource Usage**: Lower memory footprint and better resource management
4. **Streaming Processing**: Can process files larger than available RAM
5. **Predictable Performance**: No GIL limitations, better parallelism
6. **Static Typing**: Catches many errors at compile time

## Building and Installing

```bash
# Build the project
cargo build --release

# Install globally (optional)
cargo install --path .
```

## Command-Line Usage

```bash
# Analyze a single file
file_analyzer path/to/file.ext

# Analyze a directory
file_analyzer --dir path/to/directory

# Export results to multiple formats
file_analyzer example.js --json results.json --html report.html

# Get help
file_analyzer --help
```

## Library Usage

You can also use File Analyzer as a library in your Rust projects:

```rust
use file_analyzer::analyze_file;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let results = analyze_file(Path::new("path/to/file.txt"), 60)?;
    
    for (category, values) in results {
        println!("{} ({} findings):", category, values.len());
        for value in values {
            println!("  - {}", value);
        }
    }
    
    Ok(())
}
```

See the `examples` directory for more usage examples.

## Comparison with Python Version

Feature | Python Version | Rust Version
-------- | -------------- | ------------
Speed | Baseline | 5-10x faster
Memory Usage | Higher | Lower
Parallel Processing | Limited by GIL | Full concurrency
Memory Safety | Runtime checks | Compile-time guarantees
Plugin System | Yes | No (by design)
Pattern Detection | Yes | Yes
Output Formats | JSON, HTML, CSV | JSON, HTML, CSV

## Security Considerations

- Files are analyzed locally, with no data transmitted to external services
- Always handle sensitive data findings appropriately
- Be careful when analyzing unfamiliar files that might contain malicious content

## License

[MIT License](LICENSE)

## Acknowledgments

This project was inspired by various security analysis tools and incorporates best practices for sensitive data detection. 