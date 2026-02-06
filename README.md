# HopperPyMCP - FastMCP Server for Hopper Disassembler

A FastMCP server plugin for the Hopper disassembler that provides powerful analysis tools through the Model Context Protocol (MCP). This plugin allows you to analyze binary files, disassemble procedures, manage documents, and more through AI assistants.

## Features

- 🔍 **Binary Analysis**: Analyze segments, procedures, and data structures
- 🛠️ **Disassembly & Decompilation**: Get detailed assembly and pseudo-code output
- 📊 **Call Graph Generation**: Visualize function relationships and program flow
- 🔗 **Reference Analysis**: Track memory references and cross-references
- 📝 **Annotation Tools**: Add names, comments, and type information
- 🗂️ **Document Management**: Handle multiple executable files
- 🔍 **String Search**: Advanced regex-based string searching

## Quick Installation

This project uses [uv](https://docs.astral.sh/uv/) for dependency management. Install uv if needed, then run:

```bash
# Simple one-command installation (uv syncs deps and runs install)
uv run install.py
```

That's it! The script will:
- ✅ Sync dependencies from `pyproject.toml` (via uv)
- ✅ Detect your Python environment automatically
- ✅ Configure the script with correct Python paths
- ✅ Install to the appropriate Hopper Scripts directory

### Prerequisites

- **[uv](https://docs.astral.sh/uv/)** — Install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Supported Environments

- **uv** (recommended) — Uses `pyproject.toml` and `uv.lock`
- **Conda environments** (including miniconda/anaconda)
- **Python venv/virtualenv**
- **System Python installations**
- **macOS and Linux platforms**

If you use conda or venv, run the install script from within that environment; dependencies will be installed by install.py.

## Manual Installation Options

### Dry Run (Preview Changes)
```bash
# See what would be installed without making changes
uv run install.py --dry-run
```

### Force Installation
```bash
# Overwrite existing installation without prompting
uv run install.py --force
```

### Development (generate script in project for symlink)
Use `uv run install.py --dev` to generate `fastmcp_server.py` in the project directory, then symlink it into Hopper. See [Development Installation](#development-installation) below.

## Uninstallation

Remove the plugin cleanly:

```bash
# Remove the installation
uv run uninstall.py

# Preview what would be removed
uv run uninstall.py --dry-run

# Remove without confirmation
uv run uninstall.py --confirm
```

## Usage in Hopper

Once installed, the FastMCP server will be available as a script in Hopper.

### Starting the Server

After running the script in Hopper, you'll need to launch the MCP server through the Python prompt:

1. **First Time Setup - Cache Strings (Recommended)**
   
   Due to slow Hopper string APIs, the plugin creates optimized string caches for better performance. This process takes about 5-10 minutes per document and saves caches alongside your Hopper document saves.
   
   In the Hopper Python prompt, paste:
   ```python
   cache_strings()
   ```
   
   Wait for caching to complete, then launch the server:
   ```python
   launch_server_pymcp()
   ```

2. **Quick Start (Skip Caching)**
   
   To start immediately without caching (slower string searches):
   ```python
   launch_server_pymcp()
   ```

3. **Subsequent Uses**
   
   If you've already cached strings for your documents:
   ```python
   launch_server_pymcp()
   ```

The server runs and **blocks the Hopper Python console** until it stops, which keeps the connection reliable. Scripts are only available after you load at least one binary into Hopper.

Server: `http://localhost:42069/mcp/`. It provides the following tools:

### Document Management

- [`get_all_documents()`](fastmcp_server_template.py:329) - Get information about all currently opened documents (Hopper-analyzed binaries)
- [`get_current_document()`](fastmcp_server_template.py:355) - Get information about the current document with its doc_id
- [`set_current_document(doc_id)`](fastmcp_server_template.py:386) - Set the current document by doc_id
- [`rebase_document(new_base_address_hex)`](fastmcp_server_template.py:408) - Rebase the current document to a new base address

### Core Analysis Tools

- [`list_all_segments()`](fastmcp_server_template.py:424) - List all segments in the current document with basic information
- [`get_address_info(address_or_name_list)`](fastmcp_server_template.py:641) - Get comprehensive information about multiple addresses/names including segment, section, type, procedure info, and references

### Search and Discovery

- [`search_names_regex(regex_pattern, segment_name, search_type, max_results)`](fastmcp_server_template.py:459) - Search for names matching a regex pattern in a specific segment
- [`search_strings_regex(regex_pattern, segment_name, max_results)`](fastmcp_server_template.py:567) - Search for strings matching a regex pattern in a specific segment
- [`get_string_at_addr(address_hex)`](fastmcp_server_template.py:618) - Get the string content at a specific address using the cached strings list

### Disassembly & Decompilation

- [`disassemble_procedure(address_or_name)`](fastmcp_server_template.py:1008) - Disassemble a procedure into assembly language instructions
- [`decompile_procedure(address_or_name)`](fastmcp_server_template.py:973) - Decompile a procedure to C language code

### Call Graph Generation

- [`get_call_graph(start_addr_hex, direction, max_depth)`](fastmcp_server_template.py:819) - Return the call graph starting from a specific address

### Name and Symbol Analysis

- [`get_demangled_name(address_or_name)`](fastmcp_server_template.py:1086) - Get the demangled name at a specific address or for a given name

### Comments and Annotations

- [`get_comment_at_address(address_hex)`](fastmcp_server_template.py:1115) - Get the comment at a specific address
- [`set_comment_at_address(address_hex, comment)`](fastmcp_server_template.py:1133) - Set a comment at a specific address
- [`set_name_at_address(address_hex, name)`](fastmcp_server_template.py:1155) - Set a name/label at a specific address
- [`mark_data_type_at_address(address_hex, data_type, length)`](fastmcp_server_template.py:1173) - Mark data type at a specific address

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) for dependency management
- Hopper Disassembler v4 or v5
- FastMCP library (automatically installed via uv)

## File Structure

```
HopperPyMCP/
├── pyproject.toml                # Project config and dependencies
├── uv.lock                       # Locked dependency versions
├── .python-version               # Python version (3.11)
├── install.py                    # Main installation script
├── uninstall.py                  # Uninstallation script
├── fastmcp_server_template.py    # Template with placeholders
├── tests/                        # Test suite
└── README.md                     # This file
```

## Troubleshooting

### Installation Issues

**Problem**: `fastmcp` import fails after installation
```bash
# Solution: Sync dependencies with uv (recommended)
uv sync

# Or manually install with pip (if not using uv):
pip install fastmcp
# or for conda:
conda install -c conda-forge fastmcp
```

**Problem**: Permission denied when writing to Hopper directory
```bash
# Solution: Check Hopper directory permissions
ls -la ~/Library/Application\ Support/Hopper/Scripts/  # macOS
ls -la ~/GNUstep/Library/ApplicationSupport/Hopper/Scripts/  # Linux
```

**Problem**: Wrong Python environment detected
```bash
# Solution: Use uv (recommended) - it manages the environment
uv run install.py

# Or activate the correct environment first:
conda activate your-environment  # for conda
source .venv/bin/activate        # for venv
# Then run install.py
```

### Runtime Issues

**Problem**: Script not appearing in Hopper
- Verify installation path is correct for your platform
- Check Hopper Scripts directory exists and is readable
- Restart Hopper after installation

**Problem**: Import errors when running in Hopper
- The installation should handle Python path configuration automatically
- If issues persist, check that the installed script has the correct paths


### Platform-Specific Notes

**macOS**: Scripts install to `~/Library/Application Support/Hopper/Scripts/`
**Linux**: Scripts install to `~/GNUstep/Library/ApplicationSupport/Hopper/Scripts/`

## Development

### Running Tests
```bash
# Run the test suite (uv manages the environment)
uv run pytest tests/
```

### Development Installation
Generate the script in the project directory and symlink it into Hopper so you can edit the template and test without re-running the full installer:

```bash
uv run install.py --dev
# Then symlink (macOS example; Linux: ~/GNUstep/Library/ApplicationSupport/Hopper/Scripts/)
ln -s "$(pwd)/fastmcp_server.py" ~/Library/Application\ Support/Hopper/Scripts/
```

Edit `fastmcp_server_template.py`; the symlinked script in Hopper will reflect changes on next run (or restart the script in Hopper). Re-run `uv run install.py --dev` if you change only the template’s path placeholders.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the test files for usage examples
3. Open an issue on the project repository

---

**Note**: This plugin requires Hopper's built-in Python interpreter. The installation script automatically configures the necessary Python paths for seamless integration.