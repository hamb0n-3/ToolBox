#!/bin/sh

# Simple script to build the Rust project.
# Run this script directly from your terminal.

echo "Attempting to build the project..."
cargo build --target x86_64-unknown-linux-gnu --verbose

exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "Build completed successfully."
else
  echo "Build failed with exit code $exit_code."
fi

exit $exit_code 