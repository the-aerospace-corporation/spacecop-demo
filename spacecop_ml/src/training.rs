// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Model Training Pipeline
//!
//! This module orchestrates the end-to-end training process for spacecraft
//! anomaly detection models. It combines Rust-based data preprocessing with
//! Python-based neural network training.
//!
//! # Training Workflow
//!
//! ```text
//! ┌─────────────────┐
//! │ 1. Load & Parse │  Read hex strings from file
//! │    (Rust)       │  Parse to structured data
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │ 2. Group Data   │  Group by (data_type, system)
//! │    (Rust)       │  e.g., "CMD_GUIDANCE", "TLM_POWER"
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │ 3. Preprocess   │  Feature engineering
//! │    (Rust)       │  One-hot encoding
//! │                 │  Min-max scaling
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │ 4. Train Models │  Autoencoder neural networks
//! │    (Python)     │  Export to ONNX format
//! └─────────────────┘
//! ```
//!
//! # Output Structure
//!
//! For each (data_type, system) combination, the pipeline creates:
//!
//! ```text
//! scml_models/
//! ├── CMD/
//! │   └── GUIDANCE/
//! │       ├── training_data.csv           # Preprocessed features
//! │       ├── preprocessing_metadata.json # Feature definitions
//! │       ├── scaler.json                 # Scaling parameters
//! │       ├── anomaly_detector.onnx       # Trained model
//! │       └── metadata.json               # Full model metadata
//! └── TLM/
//!     └── POWER/
//!         └── ...
//! ```
//!
//! # Training Data Format
//!
//! The training file should contain one hex string per line:
//!
//! ```text
//! 1992c00000040300020500
//! 18C8C00000010D00
//! 0941e33902a5000003...
//! # Comments start with #
//! ```
//!
//! # Python Integration
//!
//! The pipeline calls `scripts/ad_models.py` to train TensorFlow models
//! and export them to ONNX format for inference in Rust.

use crate::parser::CmdTlmParser;
use crate::models::ParsedData;
use crate::preprocessing::Preprocessor;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use serde_json;
use indicatif::{ProgressBar, ProgressStyle};

/// Training pipeline coordinator.
///
/// Manages the entire training workflow from raw hex data to trained
/// ONNX models ready for deployment.
pub struct TrainingPipeline {
    /// Parser for converting hex strings to structured data
    parser: CmdTlmParser,
    /// Root directory for saving trained models
    models_dir: String,
    /// Path to Python training script
    python_script: String,
}

impl TrainingPipeline {
    /// Create a new training pipeline.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to SQLite database with packet definitions
    /// * `models_dir` - Directory to save trained models (e.g., "scml_models")
    pub fn new(db_path: &str, models_dir: &str) -> Self {
        TrainingPipeline {
            parser: CmdTlmParser::new(db_path),
            models_dir: models_dir.to_string(),
            python_script: "scripts/ad_models.py".to_string(),
        }
    }

    /// Main entry point for training from a file of hex strings.
    ///
    /// Executes the complete training workflow:
    /// 1. Load and parse training data
    /// 2. Group by (data_type, system)
    /// 3. Preprocess in Rust (feature engineering, scaling)
    /// 4. Train models in Python (TensorFlow → ONNX)
    ///
    /// # Arguments
    ///
    /// * `training_file` - Path to file containing hex strings (one per line)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, error if any step fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use spacecop_ml::TrainingPipeline;
    /// let pipeline = TrainingPipeline::new("cmd_tlm.sqlite", "scml_models");
    /// pipeline.train_from_file("data/training_cmd.txt")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn train_from_file(&self, training_file: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("=== Training Mode ===");
        println!("Training file: {}", training_file);
        println!("Models directory: {}", self.models_dir);
        println!();

        // Step 1: Load and parse training data
        println!("Step 1: Loading and parsing training data...");
        let parsed_data = self.load_and_parse_training_data(training_file)?;
        println!("  ✓ Parsed {} data points\n", parsed_data.len());

        // Step 2: Group by (data_type, system)
        println!("Step 2: Grouping data by type and system...");
        let grouped_data = self.group_by_type_and_system(parsed_data);
        println!("  ✓ Found {} unique (type, system) combinations\n", grouped_data.len());

        // Step 3: Preprocess data and save for Python
        println!("Step 3: Preprocessing data in Rust...");
        self.preprocess_and_save(&grouped_data)?;

        // Step 4: Call Python training script
        println!("\nStep 4: Training models using Python...");
        self.train_models_python()?;

        println!("\n=== Training Complete ===");
        println!("Models saved to: {}", self.models_dir);
        println!("\nYou can now run inference mode with:");
        println!("  cargo run server");

        Ok(())
    }

    /// Load hex strings from file and parse each one.
    ///
    /// Reads the training file line-by-line, parses each hex string to
    /// structured data, and collects all successfully parsed samples.
    ///
    /// # File Format
    ///
    /// - One hex string per line
    /// - Empty lines are skipped
    /// - Lines starting with `#` are treated as comments
    /// - Invalid hex strings are logged and skipped
    ///
    /// # Arguments
    ///
    /// * `filename` - Path to training data file
    ///
    /// # Returns
    ///
    /// Vector of successfully parsed data samples
    fn load_and_parse_training_data(&self, filename: &str) -> Result<Vec<ParsedData>, Box<dyn std::error::Error>> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        
        // Count total lines first for accurate progress bar
        let total_lines = reader.lines().count() as u64;
        
        // Reopen file for actual processing
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        
        // Create progress bar
        let pb = ProgressBar::new(total_lines);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} lines ({percent}%) {msg}")?
                .progress_chars("█▓▒░ ")
        );
        
        let mut parsed_data = Vec::new();
        let mut skipped = 0;
        let mut line_number = 0;

        for line in reader.lines() {
            line_number += 1;
            
            let line_content = line?.trim().to_string();
            
            // Skip empty lines and comments
            if line_content.is_empty() || line_content.starts_with('#') {
                pb.inc(1);
                continue;
            }

            let hex_str = line_content;

            // Attempt to parse the hex string
            match self.parser.parse_hex(&hex_str) {
                Ok(Some(data)) => {
                    parsed_data.push(data);
                }
                Ok(None) => {
                    // Parser returned None (ignored or unknown packet)
                    skipped += 1;
                }
                Err(e) => {
                    // Parse error - log and skip
                    pb.println(format!("  ⚠ Warning: Line {}: Failed to parse '{}': {:?}", line_number, hex_str, e));
                    skipped += 1;
                }
            }
            
            pb.inc(1);
            
            // Update progress message periodically
            if line_number % 1000 == 0 {
                pb.set_message(format!("parsed: {}, skipped: {}", parsed_data.len(), skipped));
            }
        }

        pb.finish_with_message(format!("✓ Parsed: {}, Skipped: {}", parsed_data.len(), skipped));

        Ok(parsed_data)
    }

    /// Group parsed data by (data_type, system).
    ///
    /// Organizes training samples into groups for separate model training.
    /// Each unique combination of data type (CMD/TLM) and system
    /// (e.g., GUIDANCE, POWER) gets its own model.
    ///
    /// # Arguments
    ///
    /// * `data` - Vector of all parsed training samples
    ///
    /// # Returns
    ///
    /// HashMap mapping (data_type, system) to vectors of samples
    ///
    /// # Example Groups
    ///
    /// - `("CMD", "GUIDANCE")` → All guidance commands
    /// - `("TLM", "POWER")` → All power telemetry
    fn group_by_type_and_system(&self, data: Vec<ParsedData>) -> HashMap<(String, String), Vec<ParsedData>> {
        let pb = ProgressBar::new(data.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} records")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("█▓▒░ ")
        );

        let mut grouped: HashMap<(String, String), Vec<ParsedData>> = HashMap::new();

        for datum in data {
            let key = (datum.data_type.clone(), datum.system.clone());
            grouped.entry(key).or_insert_with(Vec::new).push(datum);
            pb.inc(1);
        }

        pb.finish_with_message(format!("✓ Created {} groups", grouped.len()));
        grouped
    }

    /// Preprocess data using Rust and save for Python training.
    ///
    /// For each group:
    /// 1. Fit preprocessor (identify features, one-hot encoding)
    /// 2. Transform data to feature vectors
    /// 3. Fit scaler (compute min/max for normalization)
    /// 4. Apply scaling
    /// 5. Save preprocessed data as CSV for Python
    /// 6. Save preprocessor metadata and scaler parameters
    ///
    /// # Arguments
    ///
    /// * `grouped_data` - HashMap of (data_type, system) to training samples
    ///
    /// # Output Files (per group)
    ///
    /// - `training_data.csv`: Scaled feature vectors
    /// - `preprocessing_metadata.json`: Feature definitions
    /// - `scaler.json`: Scaling parameters
    fn preprocess_and_save(&self, grouped_data: &HashMap<(String, String), Vec<ParsedData>>) -> Result<(), Box<dyn std::error::Error>> {
        let total_groups = grouped_data.len() as u64;
        
        let pb = ProgressBar::new(total_groups);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} models {msg}")?
                .progress_chars("█▓▒░ ")
        );

        for ((data_type, system), data) in grouped_data {
            let model_name = format!("{}_{}", data_type, system);
            pb.set_message(format!("Processing {}", model_name));
            
            // Create model directory
            let model_dir = Path::new(&self.models_dir).join(data_type).join(system);
            fs::create_dir_all(&model_dir)?;

            // Step 3a: Fit preprocessor (identify features and encoding)
            let mut preprocessor = Preprocessor::fit(data)?;
            
            // Step 3b: Transform data to unscaled feature vectors
            let features_unscaled = preprocessor.transform_batch(data)?;
            
            // Validate that we got data
            if features_unscaled.is_empty() {
                pb.println(format!("    ✗ ERROR: No features extracted for {}", model_name));
                pb.inc(1);
                continue;
            }

            // Step 3c: Fit scaler (compute min/max from training data)
            preprocessor.fit_scaler(&features_unscaled)?;

            // Step 3d: Apply scaling to normalize features to [0, 1]
            let features_scaled: Vec<Vec<f64>> = features_unscaled.iter().map(|row| {
                let scaler = preprocessor.get_scaler().unwrap();
                row.iter()
                    .zip(scaler.min_.iter())
                    .zip(scaler.scale_.iter())
                    .map(|((x, min_val), scale_val)| (x * scale_val) + min_val)
                    .collect()
            }).collect();

            // Step 3e: Save preprocessed data as CSV for Python
            let data_path = model_dir.join("training_data.csv");
            match preprocessor.save_numpy_data(&features_scaled, &data_path) {
                Ok(_) => {
                    // Verify the file was created and has content
                    if let Ok(metadata) = fs::metadata(&data_path) {
                        if metadata.len() == 0 {
                            pb.println(format!("    ✗ WARNING: Empty file for {}", model_name));
                        }
                    }
                },
                Err(e) => {
                    pb.println(format!("    ✗ ERROR saving data for {}: {}", model_name, e));
                    pb.inc(1);
                    continue;
                }
            }

            // Step 3f: Save preprocessor metadata and scaler
            preprocessor.save(&model_dir)?;
            
            // Also save preprocessing metadata separately for Python to read
            let metadata_path = model_dir.join("preprocessing_metadata.json");
            let metadata_json = serde_json::to_string_pretty(preprocessor.get_metadata())?;
            let mut file = File::create(metadata_path)?;
            file.write_all(metadata_json.as_bytes())?;
            
            pb.inc(1);
        }

        pb.finish_with_message(format!("✓ Preprocessed {} models", total_groups));
        Ok(())
    }

    /// Detect the correct Python command for the platform.
    ///
    /// Searches for Python in the following order:
    /// 1. Virtual environment (if active or present in current directory)
    /// 2. System Python (`python3` or `python`)
    ///
    /// # Returns
    ///
    /// Path or command to use for running Python
    fn get_python_command(&self) -> String {
        // Check environment variable first (active venv)
        if let Ok(venv_path) = std::env::var("VIRTUAL_ENV") {
            let venv_python = if cfg!(windows) {
                format!("{}\\Scripts\\python.exe", venv_path)
            } else {
                format!("{}/bin/python", venv_path)
            };
            if Path::new(&venv_python).exists() {
                return venv_python;
            }
        }

        // Try to find venv in current directory
        let venv_paths = if cfg!(windows) {
            vec![
                ".\\venv\\Scripts\\python.exe",
                ".\\env\\Scripts\\python.exe",
            ]
        } else {
            vec![
                "./venv/bin/python",
                "./env/bin/python",
            ]
        };

        for path in venv_paths {
            if Path::new(path).exists() {
                return path.to_string();
            }
        }

        // Fall back to system Python
        if cfg!(windows) {
            if Command::new("python").arg("--version").output().is_ok() {
                return "python".to_string();
            }
            "python3".to_string()
        } else {
            if Command::new("python3").arg("--version").output().is_ok() {
                return "python3".to_string();
            }
            "python".to_string()
        }
    }

    /// Call Python training script to train all models.
    ///
    /// Executes `scripts/ad_models.py` to:
    /// 1. Load preprocessed CSV data
    /// 2. Train autoencoder neural networks (TensorFlow/Keras)
    /// 3. Calculate anomaly thresholds
    /// 4. Export models to ONNX format
    /// 5. Save metadata
    ///
    /// # Python Requirements
    ///
    /// The Python environment must have:
    /// - `tensorflow` (or `tensorflow-cpu`)
    /// - `numpy`
    /// - `tf2onnx`
    ///
    /// Install with: `pip install tensorflow numpy tf2onnx`
    ///
    /// # Returns
    ///
    /// `Ok(())` if training succeeds, error otherwise
    fn train_models_python(&self) -> Result<(), Box<dyn std::error::Error>> {
        let python_cmd = self.get_python_command();
        
        println!("  Using Python command: {}", python_cmd);
        
        let using_venv = std::env::var("VIRTUAL_ENV").is_ok();
        if using_venv {
            println!("  Detected virtual environment: {}", std::env::var("VIRTUAL_ENV").unwrap());
        } else {
            println!("  ⚠ Warning: No virtual environment detected.");
        }
        println!();

        // Build command with unbuffered output
        let mut cmd = Command::new(&python_cmd);
        cmd.arg("-u")  // Unbuffered output (real-time progress)
            .arg(&self.python_script)
            .arg("--models-dir")
            .arg(&self.models_dir)
            .arg("--train-only")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set PYTHONUNBUFFERED environment variable as backup
        cmd.env("PYTHONUNBUFFERED", "1");

        let mut child = cmd.spawn()?;

        // Get handles to stdout and stderr
        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");

        // Create readers
        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        // Spawn threads to read stdout and stderr concurrently
        // This prevents deadlocks from full pipe buffers
        let stdout_handle = std::thread::spawn(move || {
            for line in stdout_reader.lines() {
                if let Ok(line) = line {
                    println!("  {}", line);
                }
            }
        });

        let stderr_handle = std::thread::spawn(move || {
            for line in stderr_reader.lines() {
                if let Ok(line) = line {
                    eprintln!("  {}", line);
                }
            }
        });

        // Wait for both threads to complete
        stdout_handle.join().expect("stdout thread panicked");
        stderr_handle.join().expect("stderr thread panicked");

        // Wait for the child process to finish
        let status = child.wait()?;

        println!();
        if status.success() {
            println!("  ✓ Python training completed successfully");
        } else {
            eprintln!("  ✗ Python training failed with exit code: {:?}", status.code());
            eprintln!("\n  Troubleshooting:");
            eprintln!("    1. Make sure Python is installed and in PATH");
            eprintln!("    2. Activate your virtual environment if you have one:");
            eprintln!("       Windows: .\\venv\\Scripts\\activate");
            eprintln!("       Unix:    source venv/bin/activate");
            eprintln!("    3. Install required packages:");
            eprintln!("       pip install tensorflow numpy tf2onnx");
            return Err("Python training script failed".into());
        }

        Ok(())
    }
}