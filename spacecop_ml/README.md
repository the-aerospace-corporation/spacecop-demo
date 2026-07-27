# SpaceCOP ML

A real-time anomaly detection system for spacecraft command and telemetry data, written in Rust with Python-based machine learning training. This system parses CFS commands and telemetry, runs them through autoencoder neural networks for anomaly detection, and sends alerts to subscribers when anomalies are detected.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Flow](#system-flow)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [Development](#development)

## Overview

This system is designed to run onboard a spacecraft to detect anomalies in commanding (CMD) and telemetry (TLM) data in real-time. Key features include:

- **Real-time Processing**: Listens on a TCP port for hex-encoded data streams
- **CFS Parsing**: Uses a SQLite database to parse hex data into ML-useful formats
- **ML-Based Detection**: Uses autoencoder neural networks for anomaly detection
- **Model Specificity**: Separate models for each (data_type, system) combination
- **Dual Mode**: Training mode (ground) and inference mode (onboard spacecraft)
- **Zero Training/Serving Skew**: Same preprocessing code used in both training and inference

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         TRAINING MODE (Ground)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Hex Data File  →  Rust Parser  →  Python Training              │
│  (training.txt)     (parse hex)     (train autoencoders)        │
│                          ↓                    ↓                 │
│                    JSON Groups         ONNX Models              │
│                    by system           + Metadata               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    INFERENCE MODE (Spacecraft)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Port 9111      →    Parser     →   Preprocessor   →   Model    │
│  (hex input)         (SQLite)        (normalize)        (ONNX)  │
│                                                            ↓    │
│                                                      Anomaly?   │
│                                                            ↓    │
│  Port 9112      ←    JSON Alert  ←   Send to     ←   Result    │
│  (alert output)         (to SpaceCOP)            SpaceCOP      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## System Flow

### Training Flow

1. **Input**: Hex data file containing known-good commands and telemetry
2. **Parsing**: Rust reads each hex string and parses it using the SQLite database
3. **Grouping**: Data is grouped by `(CMD/TLM, SYSTEM_NAME)` combinations
4. **JSON Export**: Grouped data is saved as JSON files for Python training
5. **Python Training**: 
   - Preprocesses data (one-hot encoding, normalization)
   - Determines architecture based on feature count
   - Trains autoencoder neural network
   - Calculates anomaly threshold (99th percentile)
   - Exports to ONNX format for Rust inference
6. **Output**: ONNX models + metadata + scaler parameters saved per system

### Inference Flow

1. **Startup**: Server loads all ONNX models from `scml_models/` directory
2. **Connection**: Client connects to port 9111 and sends hex data (one per line)
3. **Parsing**: Hex string is parsed using SQLite database schema
4. **Model Selection**: System selects appropriate model based on data type and system
5. **Preprocessing**: Data is preprocessed using saved scaler parameters
6. **Inference**: ONNX model runs inference to reconstruct input
7. **Anomaly Detection**: MSE compared against threshold
8. **Alert**: If anomaly detected, JSON alert sent to SpaceCOP on port 9112

## Project Structure

```
spacecraft-anomaly-detection/
├── src/
│   ├── main.rs                 # Entry point, command-line interface
│   ├── lib.rs                  # Public API exports
│   ├── models.rs               # Data structures (Command, Telemetry, ParsedData)
│   ├── parser.rs               # Hex parser using SQLite database
│   ├── preprocessing.rs        # Shared preprocessing logic (Rust)
│   ├── anomaly_detector.rs     # ONNX model loading and inference
│   ├── training.rs             # Training pipeline orchestration
│   ├── server.rs               # TCP server for real-time inference
│   └── data/
│       ├── cmd_tlm.sqlite      # Command/telemetry definitions database
│       └── training_cmd.txt    # Training data (hex strings)
│
├── scripts/
│   ├── ad_models.py            # Python training script (autoencoders)
│   └── server_test.py          # Testing utility for TCP communication
│
├── scml_models/                # Trained models directory
│   ├── CMD/
│   │   └── SYSTEM_NAME/
│   │       ├── anomaly_detector.onnx     # ONNX model
│   │       ├── metadata.json             # Training metadata + preprocessing config
│   │       ├── scaler.json               # MinMaxScaler parameters
│   │       └── training_data.json        # Parsed training data
│   └── TLM/
│       └── SYSTEM_NAME/
│           └── ...
│
├── Cargo.toml                  # Rust dependencies
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Installation

### Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Python 3.8+**: With pip
- **SQLite**: Usually included with Python
- **COSMOS Definition Files**: For building the database (see below)

### Quick Start

```bash
# 1. Install Rust dependencies
cargo build --release

# 2. Setup Python environment
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Unix/MacOS

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Build the command/telemetry database
cd scripts
python build_database.py /path/to/nos3
cd ..

# 5. Train models (if you have training data)
cargo run -- train src/data/training_cmd.txt

# 6. Start the server
cargo run -- server
```

**For detailed setup** including proxy configuration, troubleshooting, and offline installation, see **[SETUP.md](SETUP.md)**.

### Database Setup

The database (`instance/cmd_tlm.sqlite`) must be created before the system can parse hex data. Build it from COSMOS definition files:

```bash
cd scripts
python build_database.py /path/to/nos3
```

This script parses `*_cmd.txt` and `*_tlm.txt` files and creates the SQLite database. See [SETUP.md](SETUP.md) for details.

### Rust Dependencies

The project uses these key Rust crates:
- `tract-onnx`: ONNX runtime for model inference
- `rusqlite`: SQLite database access
- `serde_json`: JSON serialization
- `ndarray`: Multi-dimensional arrays
- `indicatif`: Progress bars

Install automatically via:
```bash
cargo build
```

### Python Dependencies

Create a virtual environment and install dependencies:

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

## Building for the Raspberry Pi (cross-compilation)

`spacecop_ml` pulls in `tract-onnx`, a very large dependency tree. Compiling it
`--release` **on a Pi Zero 2 W (512 MB RAM) is not practical** — it exhausts RAM
and thrashes swap for hours, or gets OOM-killed. Build on a faster machine and
copy the binary over. Three methods below, simplest to most portable.
**Method C (static musl) is recommended** — its binary has no libc dependency,
so it runs on any Pi OS (Bullseye, Trixie, …) regardless of glibc version.

### First: pick your target triple

Run `uname -m` on the Pi:

| `uname -m` | Pi OS | glibc triple | static musl triple | cross-linker apt pkg |
|---|---|---|---|---|
| `armv7l` | 32-bit | `armv7-unknown-linux-gnueabihf` | `armv7-unknown-linux-musleabihf` | `gcc-arm-linux-gnueabihf` |
| `aarch64` | 64-bit | `aarch64-unknown-linux-gnu` | `aarch64-unknown-linux-musl` | `gcc-aarch64-linux-gnu` |

Substitute `<TRIPLE>` / `<MUSL_TRIPLE>` below with the matching row.

### Method A — Native build on the Pi (only Pi 4 / 5 with real RAM)

```bash
cd /opt/pisat/spacecop_ml
cargo build --release            # -> target/release/spacecop_ml
```
On a Zero 2 W this OOMs. If you must build on a low-RAM Pi: add 2–4 GB swap
first, then `cargo build --release -j 1` (lower peak RAM, slower).

### Method B — Cross-compile, dynamic / glibc (fast, but glibc must match)

Smaller, dynamically-linked binary. **Caveat:** it links the *build machine's*
glibc, so it only runs if the Pi's glibc is **≥ the build box's**. If the build
box is newer (as ours was), you get `version 'GLIBC_2.xx' not found` at runtime
— use Method C instead.

```bash
rustup target add <TRIPLE>
sudo apt install <cross-linker apt pkg>          # from the table above

# linker env var = CARGO_TARGET_<TRIPLE UPPERCASED, - and . -> _>_LINKER
# armv7 example:
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
# aarch64 example:
# export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

cargo build --release --target <TRIPLE>          # -> target/<TRIPLE>/release/spacecop_ml
```

### Method C — Cross-compile, static musl (RECOMMENDED, runs anywhere)

Fully static binary, **no libc dependency** — runs on any Bullseye/Trixie/other
armv7/aarch64 Linux. Uses `cargo-zigbuild`; zig ships a complete cross toolchain
so it also compiles tract's C/asm build scripts. No sudo needed.

One-time setup on the build box:
```bash
rustup target add <MUSL_TRIPLE>
python3 -m pip install --user --break-system-packages ziglang   # provides zig
cargo install cargo-zigbuild
# If cargo install errors that it needs a newer rustc, pin a compatible version,
# e.g. for rustc 1.87:  cargo install cargo-zigbuild --version 0.21.8
```

Build:
```bash
cd spacecop_ml
cargo zigbuild --release --target <MUSL_TRIPLE>  # -> target/<MUSL_TRIPLE>/release/spacecop_ml
```

Verify it's static:
```bash
file target/<MUSL_TRIPLE>/release/spacecop_ml                 # "... statically linked"
readelf -d target/<MUSL_TRIPLE>/release/spacecop_ml | grep -c NEEDED   # -> 0
```

### Deploy the binary to the Pi

Copy the built binary to where the service expects it, then restart:

```bash
# from the build box (source dir = whichever target you built into):
scp target/<MUSL_TRIPLE>/release/spacecop_ml pi@<PI_IP>:/tmp/spacecop_ml

# on the Pi:
sudo install -m 755 /tmp/spacecop_ml /opt/pisat/spacecop_ml/target/release/spacecop_ml
sudo systemctl restart pisat-ml
journalctl -u pisat-ml -n 30 --no-pager          # expect startup + connect to SpaceCop :9112
```

> `pisat-ml.service` runs `target/release/spacecop_ml server` from
> `WorkingDirectory=/opt/pisat/spacecop_ml`, and the server uses relative paths
> (`instance/`, `scml_models/`) — keep those directories alongside the binary.

## Usage

### 1. Training Mode

Note: Training data was collected via Wireshark monitoring all UDP traffic between Flight Software, Groundstation, and Simulator in distributed nos3 setup with SpaceCOP running. Data was extracted using the below command with `tshark`.

```bash
tshark -r yourfile.pcapng -T fields -E header=y -E separator=, -e frame.time -e ip.src -e ip.dst -e data -e udp.dstport > output.csv
```

Train models from hex data file:

```bash
# Activate Python virtual environment first
.\venv\Scripts\activate  # Windows
source venv/bin/activate # Unix

# Run training
cargo run -- train src/data/training_cmd.txt
```

**What happens:**
1. Rust parses all hex strings from the file
2. Groups data by system
3. Saves JSON files to `scml_models/CMD/SYSTEM_NAME/training_data.json`
4. Calls Python script to train autoencoders
5. Python exports ONNX models + metadata

**Expected output:**
```
=== Training Mode ===
Training file: src/data/training_cmd.txt
Models directory: scml_models

Step 1: Loading and parsing training data...
  Parsed 1523 data points

Step 2: Grouping data by type and system...
  Found 3 unique (type, system) combinations:
    CMD_ARDUCAM: 512 samples
    CMD_NOVATEL_OEM615: 489 samples
    CMD_GENERIC_REACTION_WHEEL: 522 samples

Step 3: Saving training data for each model...
  Saved: scml_models\CMD\ARDUCAM\training_data.json
  Saved: scml_models\CMD\NOVATEL_OEM615\training_data.json
  Saved: scml_models\CMD\GENERIC_REACTION_WHEEL\training_data.json

Step 4: Training models using Python...
  Using Python command: python
  This may take a few minutes...

============================================================
Training model: CMD_ARDUCAM
============================================================
Original data shape: (512, 15)
Columns: ['name', 'CCSDS_STREAMID', 'CCSDS_SEQUENCE', ...]
...
Model exported to ONNX format: scml_models\CMD\ARDUCAM\anomaly_detector.onnx
✓ Successfully trained CMD_ARDUCAM

=== Training Complete ===
Models saved to: scml_models
```

### 2. Inference Mode (Server)

Run the real-time anomaly detection server:

```bash
cargo run -- server
```

**What happens:**
1. Loads all ONNX models from `scml_models/`
2. Starts TCP server on port 9111 (input)
3. Attempts to connect to SpaceCOP on port 9112 (alerts output)
4. Waits for data connections

**Expected output:**
```
Using database at: src/data/cmd_tlm.sqlite
Loaded anomaly detector: CMD_ARDUCAM
Loaded anomaly detector: CMD_NOVATEL_OEM615
Loaded anomaly detector: TLM_IMU
Loaded 3 anomaly detection models
Starting Hex Parser Broadcast Server with Anomaly Detection...
  Input port (hex):  9111
  SpaceCOP alert port: 9112
Attempting to connect to SpaceCOP at localhost:9112
Hex input server listening on port 9111
```

### 3. Testing with Python Script

Use the provided test script to interact with the server:

```bash
python scripts/server_test.py
```

**Options:**
1. **Start simulated spacecop server (port 9112)** - Receives JSON alerts
2. **Send data interactively (port 9111)** - Manual hex input
3. **Batch send test data** - Send multiple test messages
4. **Batch send from file** - Send all hex strings from a file
5. **Integrated test** - Both send and receive in one script

**Recommended workflow:**

**Terminal 1:**
```bash
cargo run server
```

**Terminal 2:**
```bash
python scripts/server_test.py
# Choose option 1 (Listen)
```

**Terminal 3:**
```bash
python scripts/server_test.py
# Choose option 3 (Batch send test data)
```

**Terminal 2 will show:**
```json
[RECEIVED] {
  "data": {
    "data_type": "CMD",
    "system": "ARDUCAM",
    "name": "CAM_SEND_HK_CC",
    "parameters": [
      {
        "name": "CCSDS_STREAMID",
        "value": {
          "type": "uint",
          "value": 6345,
          "hex": "0x18C9"
        }
      },
      ...
    ]
  },
  "anomaly_detection": {
    "is_anomaly": false,
    "mse": 0.0123,
    "threshold": 0.05,
    "responsible_feature": "CCSDS_SEQUENCE"
  }
}
```

### 4. Run Test Cases

Run built-in test cases:

```bash
cargo run
```

This parses example hex strings and prints the results without starting the server.

## How It Works

### File Descriptions

#### Rust Files

**`src/main.rs`**
- Entry point for the application
- Parses command-line arguments (`server`, `train <file>`, or test mode)
- Initializes database path and models directory
- Routes to appropriate mode

**`src/lib.rs`**
- Public API exports for the library
- Re-exports key types and functions for external use

**`src/models.rs`**
- Data structure definitions:
  - `Command`, `CommandParameter`: Database schema for commands
  - `TelemetryPacket`, `TelemetryItem`: Database schema for telemetry
  - `ParsedData`, `ParsedValue`: Parsed hex data representation
  - `ParsedDataJson`: JSON-serializable format for output

**`src/parser.rs`**
- **Core parsing logic**
- `CmdTlmParser` struct:
  - Opens SQLite database connection
  - Identifies data type (CMD/TLM) from hex prefix
  - Matches APP_ID and function codes
  - Extracts bit fields from hex strings
  - Handles endianness, data types, and state mappings
  - Returns structured `ParsedData`

**`src/preprocessing.rs`**
- **Shared preprocessing between training and inference**
- `Preprocessor` struct:
  - Loads metadata and scaler from JSON files
  - Transforms parsed data into feature vectors
  - Handles one-hot encoding for categorical variables
  - Applies MinMaxScaler normalization
  - Ensures exact same preprocessing as training

**`src/anomaly_detector.rs`**
- **ONNX model inference**
- `AnomalyDetector` struct:
  - Loads ONNX model using `tract`
  - Loads preprocessing metadata
  - Runs inference on preprocessed data
  - Calculates reconstruction MSE
  - Compares against threshold
  - Identifies responsible feature
- `AnomalyDetectionSystem` struct:
  - Manages multiple detectors
  - Routes data to correct model based on type/system

**`src/training.rs`**
- **Training pipeline orchestration**
- `TrainingPipeline` struct:
  - Reads hex strings from file
  - Parses using `CmdTlmParser`
  - Groups by `(data_type, system)`
  - Saves JSON training data
  - Calls Python training script
  - Handles cross-platform Python execution

**`src/server.rs`**
- **Real-time TCP server**
- `BroadcastServer` struct:
  - Listens on port 9111 for hex input
  - Connects to SpaceCOP on port 9112 as a client
  - Parses incoming hex strings
  - Runs anomaly detection
  - Sends JSON alerts to SpaceCOP when anomalies detected
  - Automatically reconnects if connection is lost
  - Handles multiple input connections via threading

#### Python Files

**`scripts/ad_models.py`**
- **Machine learning training**
- `AutoencoderForAnomalyDetection` class:
  - Preprocesses data (one-hot encoding, normalization)
  - Saves preprocessing metadata for Rust
  - Creates autoencoder with dynamic architecture
  - Trains on reconstruction task
  - Calculates anomaly threshold (99th percentile)
  - Exports to ONNX format
  - Saves scaler parameters as JSON
- `train_all_models()` function:
  - Iterates through all subdirectories
  - Trains one model per system
  - Handles errors gracefully

**`scripts/server_test.py`**
- **Testing utility**
- Functions:
  - `send_mode()`: Interactive hex input to port 9111
  - `batch_send_mode()`: Send multiple hex strings

#### Data Files

**`src/data/cmd_tlm.sqlite`**
- SQLite database containing:
  - Command definitions (APP_ID, function codes, parameters)
  - Telemetry packet definitions (APP_ID, items, units)
  - Parameter types, bit lengths, endianness
  - State mappings (enum values)
- Generated by separate script (not included)

**`src/data/training_cmd.txt`**
- Text file with one hex string per line
- Known-good commands/telemetry for training
- Example:
  ```
  0x1926C00000010000
  1992c00000040300020500
  1871c00000000100
  18c9c00000010000
  ```

#### Model Files

**`scml_models/CMD|TLM/SYSTEM_NAME/anomaly_detector.onnx`**
- ONNX format neural network
- Autoencoder architecture (e.g., 64→32→16→32→64)
- Trained to reconstruct input features
- Loaded by `tract-onnx` for inference

**`scml_models/CMD|TLM/SYSTEM_NAME/metadata.json`**
- Training metadata:
  - Number of training samples
  - Anomaly threshold
  - False positive rate
  - Score range (min/max MSE)
- Preprocessing metadata:
  - Feature column names (after one-hot encoding)
  - Numeric column names
  - Categorical valid values
  - Encoding strategy

**`scml_models/CMD|TLM/SYSTEM_NAME/scaler.json`**
- MinMaxScaler parameters:
  - `min_`: Minimum values per feature
  - `scale_`: Scale factors per feature
  - `data_min_`, `data_max_`, `data_range_`: Training data statistics
  - `feature_range`: Output range (usually [0, 1])

**`scml_models/CMD|TLM/SYSTEM_NAME/training_data.json`**
- Parsed training data in JSON format
- Used by Python for training
- Array of objects with parameter name/value pairs

## Testing

### Unit Testing

Run Rust unit tests:
```bash
cargo test
```

### Integration Testing

1. **Parse Test**:
   ```bash
   cargo run
   ```
   Verifies parser works on example hex strings

2. **Training Test**:
   ```bash
   cargo run -- train src/data/training_cmd.txt
   ```
   Verifies end-to-end training pipeline

3. **Server Test**:
   ```bash
   # Terminal 1
   cargo run -- server
   
   # Terminal 2
   python scripts/server_test.py
   # Choose option 5 (Integrated test)
   ```
   Verifies real-time inference

### Manual Testing

Send hex strings via netcat (if available):
```bash
echo "1871c00000000100" | nc localhost 9111
```

Or use telnet:
```bash
telnet localhost 9111
1871c00000000100
```

## Development

### Adding New Systems

1. Update `cmd_tlm.sqlite` with new command/telemetry definitions
2. Add training data for the new system to training file
3. Run training mode to generate new models
4. Models automatically loaded on next server start

### Modifying Model Architecture

Edit `scripts/ad_models.py`:
```python
def create_model(self, input_dim: int):
    # Modify architecture here
    # Current: input → hidden → encoding_dim → hidden → output
```

### Adjusting Anomaly Threshold

Threshold is calculated as 99th percentile of training MSE. To adjust:
```python
# In ad_models.py, line ~XXX
threshold = np.percentile(mse, 99)  # Change 99 to different percentile
```

### Custom Preprocessing

Modify `src/preprocessing.rs` `transform()` method for custom feature engineering. Make sure to update Python preprocessing in `ad_models.py` to match!

## Troubleshooting

### "No model found for CMD_SYSTEM"
- **Cause**: Model not trained for this system
- **Solution**: Add training data and run training mode

### "Python training script failed"
- **Cause**: Missing Python dependencies or wrong Python version
- **Solution**: Activate venv, install dependencies with pip

### "Connection refused" when starting server
- **Cause**: SpaceCOP not running on port 9112
- **Solution**: Start SpaceCOP first, or server will retry connection when anomalies are detected

### Ctrl+C doesn't work in Python script
- **Cause**: Blocking socket operations
- **Solution**: Use the updated `server_test.py` with timeouts

### "Failed to load ONNX model"
- **Cause**: Model file corrupted or wrong format
- **Solution**: Re-run training mode to regenerate

## License

[Your License Here]

## Authors

Dominic Berry - Python ML code Rust implementation and integration (April 2026)
With help from Astro (astro.aero.org, claude-4.5-sonnet, April 2026)

## Acknowledgments

- Uses `tract` for ONNX inference
- Uses TensorFlow/Keras for training