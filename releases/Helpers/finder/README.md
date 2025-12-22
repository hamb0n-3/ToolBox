# Finder

Finder is a command-line search helper for oversized repositories. It looks through file names, directory names, and file contents without getting in the way.

## Features

- Handles large repositories without slowing down
- Choose whether to search file names, directory names, file contents, or all of them
- Regular expression support
- Toggle case sensitivity per run
- Optional progress indicator
- Skip binary files when they are just noise
- Follow symbolic links when you actually need them
- Limit how deep the walk goes
- Respects `.gitignore` files
- Optional content indexing for faster follow-up searches

## Installation

Ensure you have Rust and Cargo installed, then:

```bash
# Clone the repository
git clone https://github.com/yourusername/finder.git
cd finder

# Build in release mode for maximum performance
cargo build --release

# Optional: install to your path
cargo install --path .
```

## Indexing (Experimental)

Finder supports creating an index of your codebase's file contents. This experimental feature can speed up content searches after an initial indexing pass. The index is stored in a SQLite database file.

### How it Works

When you run the `index` command, Finder will:
1. Walk through the specified directory.
2. Read each file.
3. Extract alphanumeric tokens (words) from the content.
4. Store these tokens and their file locations in a SQLite database.
5. Record file modification times to only re-index changed files on subsequent runs.

This allows the `search` command, when used with the `--use-index` flag, to query this database for tokens instead of re-reading all files for content matches, which can be faster for large codebases or frequent searches.

## Usage

The `finder` tool has two main subcommands: `search` (the default behavior) and `index`.

```bash
# --- Indexing ---

# Index the current directory, saving to 'finder.db'
finder index .

# Index a specific path and specify a custom database file
finder index /path/to/your/project --db-path /path/to/project.db

# --- Searching ---

# Basic usage - search for "example" in the current directory (no index used)
finder search "example" 
# Note: 'search' can be omitted if it's the first argument that isn't a flag
# finder "example" 

# Search only in file names (no index used)
finder search --mode FileName "example"

# Search only in directory names (no index used)
finder search --mode DirName "example"

# Search only in file contents (no index used by default)
finder search --mode Content "example"

# Search file contents USING the pre-built index (experimental)
# Assumes 'finder.db' exists in the current directory or the directory being searched.
finder search --mode Content "my_token" --use-index

# Search file contents using a specific index database
finder search --mode Content "my_token" --use-index --db-path /path/to/project.db

# Search using a regular expression (cannot use index for regex content search yet)
finder search --regex "foo.*bar"

# Case sensitive search
finder --case-sensitive "Example"

# Search a specific directory
finder "example" /path/to/search

# Limit search depth
finder --max-depth 3 "example"

# Follow symbolic links
finder --follow-links "example"

# Turn off binary file filtering
finder --ignore-binary false "example"

# Turn off progress indication
finder --progress false "example"
```

## Command Line Options

Finder uses subcommands.

### Global Options (apply to `finder` itself)

```
Usage: finder [GLOBAL OPTIONS] <SUBCOMMAND>

Global Options:
      --log-level <LEVEL>  Set the logging level (error, warn, info, debug, trace)
      --log-file <PATH>    Path to a file to write logs to (e.g., finder.log)
  -h, --help               Print help
  -V, --version            Print version
```

### `search` Subcommand

```
Usage: finder search [OPTIONS] <PATTERN> [PATH]

Arguments:
  <PATTERN>                    The pattern to search for
  [PATH]                       The root directory to start searching from [default: .]

Options:
  -m, --mode <MODE>              Search mode (file-name, dir-name, content, all) [default: all]
  -r, --regex                    Use regex pattern matching for PATTERN.
                                 When searching content, this will not use the index.
  -c, --case-sensitive           Case sensitive search (default is case insensitive for simple patterns,
                                 and respects regex flags for --regex).
  -i, --ignore-binary <BOOL>     Ignore binary files when searching content [default: true]
  -f, --follow-links             Follow symbolic links
  -d, --max-depth <MAX_DEPTH>    Maximum depth to search
  -p, --progress <BOOL>          Show progress bar [default: true]
      --use-index                Use the pre-built index for content searching (experimental).
                                 Only effective with --mode Content or --mode All.
                                 Cannot be used with --regex for content search.
      --db-path <DB_PATH>        Path to the SQLite database file to use for indexed search
                                 [default: finder.db]
  -h, --help                     Print help
```

### `index` Subcommand

```
Usage: finder index [OPTIONS] [PATH]

Arguments:
  [PATH]     The root directory to index [default: .]

Options:
      --db-path <DB_PATH>  Path to the SQLite database file to create/update
                           [default: finder.db]
  -h, --help               Print help
```

## Performance Tips

1. For large codebases, use the `--mode` flag to limit the search scope (e.g., `FileName`, `DirName`).
2. After an initial (potentially long) indexing pass using `finder index`, subsequent content searches with `finder search --mode Content --use-index` can be significantly faster.
3. The `--max-depth` option can significantly improve performance for both searching and indexing when you only need to operate to a certain depth.
4. When searching file contents in large codebases without an index, results will appear as they're found.
5. Regular expression searches on content currently do not use the index and will scan files directly.

## License

MIT 
