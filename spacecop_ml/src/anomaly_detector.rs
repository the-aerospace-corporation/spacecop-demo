// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop
// All rights reserved.
//
// This software is provided "as is" without any warranty of any kind either express, implied, or statutory, including, but not
// limited to, any warranty that the software will conform to specifications any implied warranties of merchantability, fitness
// for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
// any warranty that the software will be error free.
//
// In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
// arising out of, resulting from, or in any way connected with the software or its documentation. Whether or not based upon warranty,
// contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
// documentation or services provided hereunder
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Dominc Berry (dominic.t.berry@aero.org)
// Brandon Bailey (brandon.bailey@aero.org)

//! Anomaly Detection Module
//!
//! This module provides machine learning-based anomaly detection for spacecraft
//! command and telemetry data using autoencoder neural networks.
//!
//! # Components
//!
//! - **AnomalyDetector**: ONNX-based autoencoder for detecting anomalous patterns
//! - **AlertTracker**: Prevents duplicate alerts with cooldown periods
//! - **RateMonitor**: Detects command flooding attacks
//! - **AnomalyDetectionSystem**: Orchestrates multiple detectors and monitors
//!
//! # Architecture
//!
//! The system uses reconstruction error (MSE) from autoencoders to identify
//! anomalies. Each spacecraft system has its own trained model that learns
//! normal operational patterns during training.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tract_onnx::prelude::*;
use crate::preprocessing::{Preprocessor, PreprocessingMetadata};
use crate::models::ParsedData;

/// Metadata describing a trained anomaly detection model.
///
/// This structure contains both preprocessing information and training statistics
/// that are persisted alongside the ONNX model file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Preprocessing parameters (feature scaling, encoding, etc.)
    pub preprocessing: PreprocessingMetadata,
    /// Training statistics and model configuration
    pub training: TrainingMetadata,
}

/// Training statistics and model configuration.
///
/// Contains information about the training process, including the anomaly
/// detection threshold calculated from training data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetadata {
    /// Number of samples used during training
    pub training_samples: usize,
    /// Target false positive rate (e.g., 0.01 for 1%)
    pub false_positive_rate: f64,
    /// MSE threshold above which data is considered anomalous
    pub threshold: f64,
    /// [min, max] reconstruction error observed during training
    pub score_range: Vec<f64>,
    /// Type of model (e.g., "autoencoder")
    pub model_type: String,
}

/// Autoencoder-based anomaly detector for spacecraft data.
///
/// Uses an ONNX neural network model to detect anomalies by computing
/// reconstruction error. High reconstruction error indicates the data
/// differs significantly from learned normal patterns.
pub struct AnomalyDetector {
    /// ONNX runtime model (autoencoder)
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    /// Model metadata including threshold and training info
    metadata: ModelMetadata,
    /// Preprocessor for feature engineering and scaling
    preprocessor: Preprocessor,
}

/// Result of an anomaly detection prediction.
///
/// Contains the anomaly classification, reconstruction error metrics,
/// and identification of the most anomalous feature.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    /// True if the data is classified as anomalous
    pub is_anomaly: bool,
    /// Mean squared error (reconstruction error)
    pub mse: f64,
    /// Threshold used for classification
    pub threshold: f64,
    /// Feature with the largest reconstruction error
    pub responsible_feature: String,
}

impl AnomalyDetector {
    /// Load a trained anomaly detection model from disk.
    ///
    /// # Arguments
    ///
    /// * `model_dir` - Directory containing `anomaly_detector.onnx` and `metadata.json`
    ///
    /// # Returns
    ///
    /// Returns the loaded detector or an error if files are missing or invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    /// # use spacecop_ml::anomaly::AnomalyDetector;
    /// let detector = AnomalyDetector::load(Path::new("scml_models/CMD/SYSTEM1"))?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load(model_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        // Load ONNX model file
        let model_path = model_dir.join("anomaly_detector.onnx");
        let model = tract_onnx::onnx()
            .model_for_path(&model_path)?
            .into_optimized()?
            .into_runnable()?;

        // Load metadata JSON file
        let metadata_path = model_dir.join("metadata.json");
        let metadata_str = fs::read_to_string(metadata_path)?;
        let metadata: ModelMetadata = serde_json::from_str(&metadata_str)?;

        // Load preprocessor (scaling parameters, feature definitions)
        let preprocessor = Preprocessor::load(model_dir)?;

        Ok(AnomalyDetector {
            model,
            metadata,
            preprocessor,
        })
    }

    /// Predict whether the given data is anomalous.
    ///
    /// # Algorithm
    ///
    /// 1. Preprocess the data (feature engineering, scaling)
    /// 2. Run through autoencoder to get reconstruction
    /// 3. Calculate mean squared error (MSE) between input and reconstruction
    /// 4. Compare MSE to threshold to classify as anomaly
    /// 5. Identify the feature with the largest reconstruction error
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed command or telemetry data
    ///
    /// # Returns
    ///
    /// Returns an `AnomalyResult` with classification and error metrics.
    pub fn predict(&self, data: &ParsedData) -> Result<AnomalyResult, Box<dyn std::error::Error>> {
        // Preprocess the data into feature vector
        let input_data = self.preprocessor.transform(data)?;
        let n_features = input_data.len();

        // Create tensor for ONNX model input (1 x n_features)
        let input_tensor = tract_ndarray::Array2::from_shape_vec((1, n_features), input_data.clone())?;
        let tensor = Tensor::from(input_tensor);

        // Run inference through the autoencoder
        let result = self.model.run(tvec![tensor.into()])?;
        
        // Extract reconstructed output
        let output = result[0].to_array_view::<f32>()?;
        let reconstruction: Vec<f32> = output.iter().copied().collect();

        // Calculate squared errors for each feature
        let squared_errors: Vec<f32> = input_data
            .iter()
            .zip(reconstruction.iter())
            .map(|(x, r)| (x - r).powi(2))
            .collect();

        // Calculate mean squared error (MSE) as anomaly score
        let mse: f64 = (squared_errors.iter().sum::<f32>() / squared_errors.len() as f32) as f64;

        // Determine if anomaly based on threshold
        let threshold = self.metadata.training.threshold;
        let is_anomaly = mse > threshold;

        // Find the feature with the largest reconstruction error
        // This helps identify what aspect of the data is anomalous
        let max_deviation_idx = squared_errors
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(idx, _)| idx)
            .unwrap_or(0);

        let responsible_feature = self.preprocessor.get_metadata().feature_columns
            .get(max_deviation_idx)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        Ok(AnomalyResult {
            is_anomaly,
            mse,
            threshold,
            responsible_feature,
        })
    }
}

/// Tracks alerts to prevent duplicate notifications within a cooldown period.
///
/// Uses content-based hashing to identify identical command/telemetry messages
/// and suppress repeated alerts for the same issue.
pub struct AlertTracker {
    /// Map of data hash to last alert timestamp
    last_alerts: HashMap<u64, SystemTime>,
    /// Minimum time between alerts for the same data
    cooldown_duration: Duration,
}

impl AlertTracker {
    /// Create a new alert tracker with the specified cooldown period.
    ///
    /// # Arguments
    ///
    /// * `cooldown_seconds` - Minimum seconds between alerts for identical data
    pub fn new(cooldown_seconds: u64) -> Self {
        AlertTracker {
            last_alerts: HashMap::new(),
            cooldown_duration: Duration::from_secs(cooldown_seconds),
        }
    }

    /// Check if an alert should be sent for the given data.
    ///
    /// Computes a hash of the data content (type, system, name, and all parameters)
    /// and checks if an alert was recently sent for identical data.
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed command or telemetry data
    ///
    /// # Returns
    ///
    /// Returns `true` if an alert should be sent, `false` if still in cooldown period.
    pub fn should_alert(&mut self, data: &ParsedData) -> bool {
        // Create a hash of the actual data content
        let mut hasher = DefaultHasher::new();
        data.data_type.hash(&mut hasher);
        data.system.hash(&mut hasher);
        data.name.hash(&mut hasher);
        
        // Include all parameter values in the hash
        for (param_name, param_value) in &data.parameters {
            param_name.hash(&mut hasher);
            // Hash the value representation based on type
            match param_value {
                crate::models::ParsedValue::UInt(v) => v.hash(&mut hasher),
                crate::models::ParsedValue::Int(v) => v.hash(&mut hasher),
                crate::models::ParsedValue::Float(v) => v.to_bits().hash(&mut hasher),
                crate::models::ParsedValue::String(v) => v.hash(&mut hasher),
                crate::models::ParsedValue::State(v) => v.hash(&mut hasher),
            }
        }
        
        let data_hash = hasher.finish();
        let now = SystemTime::now();
        
        if let Some(last_time) = self.last_alerts.get(&data_hash) {
            // Check if cooldown period has elapsed
            if let Ok(elapsed) = now.duration_since(*last_time) {
                if elapsed < self.cooldown_duration {
                    // Still in cooldown period for this exact message
                    return false;
                }
            }
        }
        
        // Either first alert or cooldown expired - update timestamp
        self.last_alerts.insert(data_hash, now);
        true
    }

    /// Clean up old entries to prevent unbounded memory growth.
    ///
    /// Removes entries that are older than 2x the cooldown duration.
    /// Should be called periodically (e.g., every few minutes).
    pub fn cleanup_old_entries(&mut self) {
        let now = SystemTime::now();
        let cleanup_threshold = self.cooldown_duration * 2;
        
        self.last_alerts.retain(|_, last_time| {
            if let Ok(elapsed) = now.duration_since(*last_time) {
                elapsed < cleanup_threshold
            } else {
                true
            }
        });
    }
}

/// Monitors command rates to detect flooding attacks.
///
/// Tracks the number of commands per system within a sliding time window
/// and alerts if the rate exceeds a threshold, which may indicate a
/// denial-of-service attack or system malfunction.
pub struct RateMonitor {
    /// Track command timestamps per system (key: "CMD_SYSTEM" or "TLM_SYSTEM")
    command_history: HashMap<String, VecDeque<SystemTime>>,
    /// Time window to check (e.g., last 60 seconds)
    window_duration: Duration,
    /// Maximum commands allowed in window before flagging as flooding
    max_commands_per_window: usize,
}

impl RateMonitor {
    /// Create a new rate monitor with specified parameters.
    ///
    /// # Arguments
    ///
    /// * `window_seconds` - Size of the sliding time window
    /// * `max_commands` - Maximum commands allowed in the window
    ///
    /// # Example Configurations
    ///
    /// - Conservative: `RateMonitor::new(60, 100)` - 100 commands per minute
    /// - Balanced: `RateMonitor::new(60, 50)` - 50 commands per minute
    /// - Aggressive: `RateMonitor::new(60, 20)` - 20 commands per minute
    pub fn new(window_seconds: u64, max_commands: usize) -> Self {
        RateMonitor {
            command_history: HashMap::new(),
            window_duration: Duration::from_secs(window_seconds),
            max_commands_per_window: max_commands,
        }
    }

    /// Check if command rate is suspicious for the given system.
    ///
    /// Maintains a sliding window of command timestamps and checks if
    /// the current rate exceeds the configured threshold.
    ///
    /// # Arguments
    ///
    /// * `system` - System name (e.g., "GUIDANCE", "POWER")
    /// * `data_type` - Type of data ("CMD" or "TLM")
    ///
    /// # Returns
    ///
    /// Returns `(is_flooding, current_rate, threshold)`:
    /// - `is_flooding`: true if rate exceeds threshold
    /// - `current_rate`: current number of commands in window
    /// - `threshold`: configured maximum commands per window
    pub fn check_rate(&mut self, system: &str, data_type: &str) -> (bool, usize, usize) {
        let key = format!("{}_{}", data_type, system);
        let now = SystemTime::now();
        
        // Get or create history for this system
        let history = self.command_history
            .entry(key)
            .or_insert_with(VecDeque::new);
        
        // Add current timestamp
        history.push_back(now);
        
        // Remove timestamps outside the sliding window
        let cutoff = now - self.window_duration;
        while let Some(timestamp) = history.front() {
            if let Ok(elapsed) = now.duration_since(*timestamp) {
                if elapsed > self.window_duration {
                    history.pop_front();
                } else {
                    break;
                }
            } else {
                history.pop_front();
            }
        }
        
        let current_rate = history.len();
        let is_flooding = current_rate > self.max_commands_per_window;
        
        (is_flooding, current_rate, self.max_commands_per_window)
    }

    /// Cleanup old entries to prevent unbounded memory growth.
    ///
    /// Removes timestamps older than 2x the window duration.
    /// Should be called periodically.
    pub fn cleanup(&mut self) {
        let now = SystemTime::now();
        let cleanup_threshold = self.window_duration * 2;
        
        for history in self.command_history.values_mut() {
            while let Some(timestamp) = history.front() {
                if let Ok(elapsed) = now.duration_since(*timestamp) {
                    if elapsed > cleanup_threshold {
                        history.pop_front();
                    } else {
                        break;
                    }
                } else {
                    history.pop_front();
                }
            }
        }
        
        // Remove empty entries
        self.command_history.retain(|_, history| !history.is_empty());
    }
}

/// Unified anomaly detection system managing multiple detectors and monitors.
///
/// This is the main interface for anomaly detection, coordinating:
/// - Multiple ML models (one per system/data type)
/// - Alert deduplication
/// - Rate-based attack detection
pub struct AnomalyDetectionSystem {
    /// Root directory containing all trained models
    models_dir: PathBuf,
    /// Map of "CMD_SYSTEM" or "TLM_SYSTEM" to trained detector
    detectors: HashMap<String, AnomalyDetector>,
    /// Tracks recent alerts to prevent duplicates
    alert_tracker: std::sync::Mutex<AlertTracker>,
    /// Monitors command rates for flooding attacks
    rate_monitor: std::sync::Mutex<RateMonitor>,
}

impl AnomalyDetectionSystem {
    /// Create a new anomaly detection system and load all available models.
    ///
    /// # Arguments
    ///
    /// * `models_dir` - Root directory containing model subdirectories
    ///   (e.g., "scml_models/CMD/SYSTEM1", "scml_models/TLM/SYSTEM2")
    ///
    /// # Returns
    ///
    /// Returns the initialized system or an error if no models can be loaded.
    ///
    /// # Configuration
    ///
    /// - Alert cooldown: 30 seconds (prevents duplicate alerts)
    /// - Rate monitoring: 50 commands per 60-second window
    ///
    /// Adjust these parameters based on your operational requirements.
    pub fn new(models_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut system = AnomalyDetectionSystem {
            models_dir: models_dir.to_path_buf(),
            detectors: HashMap::new(),
            // 30 second cooldown for duplicate alerts
            alert_tracker: std::sync::Mutex::new(AlertTracker::new(30)),
            // Monitor 60-second windows, alert if >50 commands
            // Adjust these based on your normal traffic patterns:
            // RateMonitor::new(window_seconds, max_commands)
            // Examples:
            //   - Conservative: RateMonitor::new(60, 100)
            //   - Balanced:     RateMonitor::new(60, 50)
            //   - Aggressive:   RateMonitor::new(60, 20)
            rate_monitor: std::sync::Mutex::new(RateMonitor::new(60, 50)),
        };

        system.load_all_models()?;
        Ok(system)
    }

    /// Load all available models from the models directory.
    ///
    /// Scans the directory structure for trained models:
    /// - `models_dir/CMD/SYSTEM1/` -> detector for CMD_SYSTEM1
    /// - `models_dir/TLM/SYSTEM2/` -> detector for TLM_SYSTEM2
    ///
    /// Failures to load individual models are logged but don't stop the process.
    fn load_all_models(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for data_type in &["CMD", "TLM"] {
            let type_dir = self.models_dir.join(data_type);
            if !type_dir.exists() {
                continue;
            }

            for entry in fs::read_dir(type_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_dir() {
                    let system_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    
                    let key = format!("{}_{}", data_type, system_name);
                    
                    match AnomalyDetector::load(&path) {
                        Ok(detector) => {
                            println!("Loaded anomaly detector: {}", key);
                            self.detectors.insert(key, detector);
                        }
                        Err(e) => {
                            eprintln!("Failed to load model for {}: {}", key, e);
                        }
                    }
                }
            }
        }

        println!("Loaded {} anomaly detection models", self.detectors.len());
        Ok(())
    }

    /// Predict whether the given data is anomalous.
    ///
    /// Selects the appropriate model based on data type and system,
    /// then runs anomaly detection.
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed command or telemetry data
    ///
    /// # Returns
    ///
    /// Returns an `AnomalyResult` or an error if no model exists for this data type.
    pub fn predict(&self, data: &ParsedData) -> Result<AnomalyResult, Box<dyn std::error::Error>> {
        let key = format!("{}_{}", data.data_type, data.system);
        
        match self.detectors.get(&key) {
            Some(detector) => detector.predict(data),
            None => Err(format!("No model found for {}", key).into()),
        }
    }

    /// Check if an alert should be sent for this specific data.
    ///
    /// Uses the alert tracker to prevent duplicate alerts within the cooldown period.
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed command or telemetry data
    ///
    /// # Returns
    ///
    /// Returns `true` if an alert should be sent, `false` if suppressed.
    pub fn should_alert(&self, data: &ParsedData) -> bool {
        let mut tracker = self.alert_tracker.lock().unwrap();
        tracker.should_alert(data)
    }

    /// Check if command rate indicates a flooding attack.
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed command or telemetry data
    ///
    /// # Returns
    ///
    /// Returns `Some((current_rate, threshold))` if flooding is detected, `None` otherwise.
    pub fn check_flooding(&self, data: &ParsedData) -> Option<(usize, usize)> {
        let mut monitor = self.rate_monitor.lock().unwrap();
        let (is_flooding, current_rate, threshold) = monitor.check_rate(&data.system, &data.data_type);
        
        if is_flooding {
            Some((current_rate, threshold))
        } else {
            None
        }
    }

    /// Periodic cleanup of old alert and rate monitoring entries.
    ///
    /// Should be called periodically (e.g., every few minutes) to prevent
    /// unbounded memory growth from historical data.
    pub fn cleanup(&self) {
        let mut tracker = self.alert_tracker.lock().unwrap();
        tracker.cleanup_old_entries();
        drop(tracker);
        
        let mut monitor = self.rate_monitor.lock().unwrap();
        monitor.cleanup();
    }
}