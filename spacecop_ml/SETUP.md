# Setup Guide

## Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Python 3.8+**: With pip
- **Git**: For cloning the repository

## Standard Setup (Most Users)

### 1. Clone and Build Rust

```bash
cd spacecop_ml
cargo build --release
```

### 2. Setup Python Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# Windows:
.\venv\Scripts\activate
# Unix/MacOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Verify Installation

```bash
# Run tests
cargo test

# Run basic parsing test
cargo run
```

## Corporate Network / Proxy Setup

If you're behind a corporate proxy and getting network errors during `cargo build`:

### Option 1: Configure Cargo Proxy (Recommended)

Create `.cargo/config.toml` in the `spacecop_ml` directory:

```toml
[http]
proxy = "http://proxy.example.com:8080"  # Replace with your proxy
check-revoke = false

[net]
git-fetch-with-cli = true
```

**Note**: This file is gitignored and won't be committed.

### Option 2: Use Environment Variables

```bash
# Windows (PowerShell)
$env:HTTP_PROXY="http://proxy.example.com:8080"
$env:HTTPS_PROXY="http://proxy.example.com:8080"

# Windows (CMD)
set HTTP_PROXY=http://proxy.example.com:8080
set HTTPS_PROXY=http://proxy.example.com:8080

# Unix/MacOS
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
```

### Option 3: Use Vendored Dependencies (Offline)

If you have cargo dependencies already cached:

```bash
cargo vendor
```

Add to `.cargo/config.toml`:
```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

## Python Proxy Setup

If pip fails with proxy errors:

```bash
pip install -r requirements.txt --proxy http://proxy.example.com:8080
```

Or set environment variable:
```bash
# Windows
set HTTP_PROXY=http://proxy.example.com:8080
set HTTPS_PROXY=http://proxy.example.com:8080

# Unix/MacOS
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
```

## Database Setup

**IMPORTANT**: The system requires `instance/cmd_tlm.sqlite` to run. This database contains command and telemetry definitions parsed from COSMOS-format configuration files.

### Building the Database from COSMOS Definition Files

If you have access to nos3 or COSMOS configuration files (containing `*_cmd.txt` and `*_tlm.txt` files):

```bash
# Activate Python virtual environment
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Unix/MacOS

# Run the database builder
cd scripts
python build_database.py /path/to/nos3

# Example: If nos3 is in your parent directory
python build_database.py ../../nos3
```

The script will:
1. Walk through the specified directories
2. Find all `*_cmd.txt` (command) and `*_tlm.txt` (telemetry) files
3. Parse COSMOS-format definitions
4. Build the SQLite database at `instance/cmd_tlm.sqlite`

**Expected Output:**
```
Building database: ../instance/cmd_tlm.sqlite
Scanning directories: ['/path/to/components', '/path/to/gsw']

Created database schema

Processing: /path/to/components
  Parsing COMMAND: arducam_cmd.txt
  Parsing TELEMETRY: arducam_tlm.txt
  Found 15 commands, 8 telemetry packets

Processing: /path/to/gsw
  ...

============================================================
Database Build Summary
============================================================
Commands:  156
Telemetry: 89
Output:    /full/path/to/instance/cmd_tlm.sqlite
============================================================
```

### If you already have the database:
```bash
# Windows
mkdir instance
copy path\to\cmd_tlm.sqlite instance\

# Unix/MacOS
mkdir -p instance
cp /path/to/cmd_tlm.sqlite instance/
```

### If you don't have COSMOS definition files:
Contact the SpaceCOP team to obtain:
- The pre-built `cmd_tlm.sqlite` database, or
- Access to the nos3 component definitions

## Troubleshooting

### "No such file or directory: instance/cmd_tlm.sqlite"
- Create the `instance/` directory
- Ensure `cmd_tlm.sqlite` is in the correct location
- Check file permissions

### "Failed to download from crates.io"
- You're likely behind a corporate proxy
- See "Corporate Network / Proxy Setup" above
- Contact your IT department for proxy settings

### Python "ModuleNotFoundError"
- Ensure virtual environment is activated
- Reinstall requirements: `pip install -r requirements.txt`
- Check Python version: `python --version` (need 3.8+)

### "Failed to load ONNX model"
- You need to train models first: `cargo run -- train <data_file>`
- Ensure Python environment is activated during training
- Check that `scml_models/` directory was created

## Next Steps

After successful setup:

1. **Train models**: `cargo run -- train src/data/training_cmd.txt`
2. **Start server**: `cargo run -- server`
3. **Test**: See README.md for testing instructions
