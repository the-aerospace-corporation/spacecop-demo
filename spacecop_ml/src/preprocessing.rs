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

//! Data Preprocessing for Machine Learning
//!
//! This module handles feature engineering and data normalization for spacecraft
//! command and telemetry data before feeding it to ML models.
//!
//! # Preprocessing Pipeline
//!
//! 1. **Feature Extraction**: Convert parsed data to numeric features
//!    - Numeric parameters: Used directly
//!    - Categorical parameters: One-hot encoded
//!
//! 2. **Feature Scaling**: Normalize values to [0, 1] range using min-max scaling
//!
//! 3. **Missing Value Handling**: Fill missing parameters with zeros
//!
//! # Feature Engineering
//!
//! ## Numeric Features
//! - Integer and float parameters are used directly as features
//! - Example: `VOLTAGE`, `TEMPERATURE`, `COUNT`
//!
//! ## Categorical Features (One-Hot Encoding)
//! - Each unique value becomes a binary column
//! - Example: `MODE` with values ["SAFE", "NOMINAL", "STANDBY"] becomes:
//!   - `MODE_SAFE`: 1 if MODE=="SAFE", else 0
//!   - `MODE_NOMINAL`: 1 if MODE=="NOMINAL", else 0
//!   - `MODE_STANDBY`: 1 if MODE=="STANDBY", else 0
//!   - `MODE_Other`: 1 if MODE is an unseen value, else 0
//!
//! # Min-Max Scaling
//!
//! Features are scaled to [0, 1] using the formula:
//! ```text
//! scaled_value = (value - min) / (max - min)
//! ```
//!
//! This ensures all features have the same scale, which is important for
//! neural network training and anomaly detection.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use crate::models::{ParsedData, ParsedValue};

/// Metadata describing the preprocessing configuration.
///
/// Contains information about feature columns, data types, and
/// preprocessing strategies. This metadata is saved alongside
/// trained models to ensure consistent preprocessing during inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessingMetadata {
    /// Ordered list of all feature column names
    pub feature_columns: Vec<String>,
    /// List of numeric column names (subset of feature_columns)
    pub numeric_columns: Vec<String>,
    /// Valid values for each categorical parameter (for one-hot encoding)
    pub categorical_valid_values: HashMap<String, Vec<String>>,
    /// Strategy for handling missing values (e.g., "fill_with_zero")
    pub missing_value_strategy: String,
    /// Categorical encoding method (e.g., "one_hot")
    pub categorical_encoding: String,
    /// Feature scaling method (e.g., "min_max_scaler")
    pub scaling: String,
}

/// Parameters for min-max feature scaling.
///
/// Contains the statistics computed from training data needed to
/// scale features to the [0, 1] range consistently during inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalerData {
    /// Offset to apply before scaling (computed from data_min and scale)
    pub min_: Vec<f64>,
    /// Scaling factor for each feature
    pub scale_: Vec<f64>,
    /// Minimum value observed in training data for each feature
    pub data_min_: Vec<f64>,
    /// Maximum value observed in training data for each feature
    pub data_max_: Vec<f64>,
    /// Range (max - min) for each feature
    pub data_range_: Vec<f64>,
    /// Target range for scaling (typically [0.0, 1.0])
    pub feature_range: Vec<f64>,
}

/// Preprocessor for converting parsed spacecraft data to ML features.
///
/// Handles feature extraction, one-hot encoding, and min-max scaling.
/// The same preprocessor instance (or one loaded from saved parameters)
/// must be used for both training and inference to ensure consistency.
pub struct Preprocessor {
    /// Preprocessing configuration and feature definitions
    metadata: PreprocessingMetadata,
    /// Scaling parameters (fitted during training)
    scaler: Option<ScalerData>,
}

impl Preprocessor {
    /// Create a new preprocessor by analyzing training data.
    ///
    /// This method identifies all unique parameters and their types,
    /// then constructs the feature engineering pipeline.
    ///
    /// # Process
    ///
    /// 1. Scan all training samples to identify parameters
    /// 2. Classify parameters as numeric or categorical
    /// 3. For categorical parameters, collect all unique values
    /// 4. Create feature column definitions (numeric + one-hot encoded)
    ///
    /// # Arguments
    ///
    /// * `training_data` - Collection of parsed training samples
    ///
    /// # Returns
    ///
    /// A preprocessor ready to transform data (scaler not yet fitted)
    ///
    /// # Note
    ///
    /// After calling `fit()`, you must call `fit_scaler()` with preprocessed
    /// training data to complete the setup.
    pub fn fit(training_data: &[ParsedData]) -> Result<Self, Box<dyn std::error::Error>> {
        if training_data.is_empty() {
            return Err("Cannot fit preprocessor on empty data".into());
        }

        // Step 1: Identify all unique parameter names and their types
        let mut all_param_names = HashSet::new();
        let mut numeric_params = HashSet::new();
        let mut categorical_params = HashMap::new();

        for data in training_data {
            for (param_name, param_value) in &data.parameters {
                all_param_names.insert(param_name.clone());
                
                match param_value {
                    // Numeric types: integers and floats
                    ParsedValue::UInt(_) | ParsedValue::Int(_) | ParsedValue::Float(_) => {
                        numeric_params.insert(param_name.clone());
                    }
                    // Categorical types: strings and states
                    ParsedValue::String(s) | ParsedValue::State(s) => {
                        categorical_params
                            .entry(param_name.clone())
                            .or_insert_with(HashSet::new)
                            .insert(s.clone());
                    }
                }
            }
        }

        // Step 2: Create feature columns (numeric + one-hot encoded categorical)
        let mut feature_columns = Vec::new();
        let mut numeric_columns = Vec::new();

        // Add numeric columns (sorted for consistency)
        let mut numeric_params_vec: Vec<_> = numeric_params.iter().cloned().collect();
        numeric_params_vec.sort();
        for param in &numeric_params_vec {
            feature_columns.push(param.clone());
            numeric_columns.push(param.clone());
        }

        // Add one-hot encoded categorical columns
        let mut categorical_valid_values = HashMap::new();
        let mut categorical_params_vec: Vec<_> = categorical_params.keys().cloned().collect();
        categorical_params_vec.sort();
        
        for param in &categorical_params_vec {
            let mut values: Vec<_> = categorical_params[param].iter().cloned().collect();
            values.sort();
            
            // Create one-hot columns for each known value
            // Example: "MODE" with values ["SAFE", "NOMINAL"] becomes:
            //   - "MODE_SAFE"
            //   - "MODE_NOMINAL"
            for value in &values {
                feature_columns.push(format!("{}_{}", param, value));
            }
            
            // Add "Other" column for unseen values during inference
            // This handles the case where a new value appears that wasn't in training
            feature_columns.push(format!("{}_Other", param));
            
            categorical_valid_values.insert(param.clone(), values);
        }

        let metadata = PreprocessingMetadata {
            feature_columns,
            numeric_columns,
            categorical_valid_values,
            missing_value_strategy: "fill_with_zero".to_string(),
            categorical_encoding: "one_hot".to_string(),
            scaling: "min_max_scaler".to_string(),
        };

        Ok(Preprocessor {
            metadata,
            scaler: None,
        })
    }

    /// Fit the min-max scaler on preprocessed training data.
    ///
    /// Computes the minimum and maximum values for each feature across
    /// all training samples, then calculates scaling parameters to map
    /// features to the [0, 1] range.
    ///
    /// # Arguments
    ///
    /// * `data` - Preprocessed training data (output of `transform_batch`)
    ///
    /// # Formula
    ///
    /// For each feature i:
    /// ```text
    /// scale[i] = (feature_range_max - feature_range_min) / (data_max[i] - data_min[i])
    /// min[i] = -data_min[i] * scale[i] + feature_range_min
    /// ```
    ///
    /// Then during transformation:
    /// ```text
    /// scaled_value = value * scale[i] + min[i]
    /// ```
    pub fn fit_scaler(&mut self, data: &[Vec<f64>]) -> Result<(), Box<dyn std::error::Error>> {
        if data.is_empty() {
            return Err("Cannot fit scaler on empty data".into());
        }

        let n_features = data[0].len();

        // Calculate min and max for each feature across all samples
        let mut data_min = vec![f64::INFINITY; n_features];
        let mut data_max = vec![f64::NEG_INFINITY; n_features];

        for sample in data {
            for (i, &value) in sample.iter().enumerate() {
                data_min[i] = data_min[i].min(value);
                data_max[i] = data_max[i].max(value);
            }
        }

        // Calculate range and scaling parameters
        let feature_range = vec![0.0, 1.0]; // Target range: [0, 1]
        let data_range: Vec<f64> = data_min
            .iter()
            .zip(data_max.iter())
            .map(|(min, max)| max - min)
            .collect();

        // Compute scale factor for each feature
        let scale_: Vec<f64> = data_range
            .iter()
            .map(|&range| {
                if range == 0.0 {
                    1.0 // Avoid division by zero (constant features)
                } else {
                    (feature_range[1] - feature_range[0]) / range
                }
            })
            .collect();

        // Compute offset for each feature
        let min_: Vec<f64> = data_min
            .iter()
            .zip(scale_.iter())
            .map(|(&data_min_val, &scale_val)| -data_min_val * scale_val + feature_range[0])
            .collect();

        self.scaler = Some(ScalerData {
            min_,
            scale_,
            data_min_: data_min,
            data_max_: data_max,
            data_range_: data_range,
            feature_range,
        });

        Ok(())
    }

    /// Transform a single ParsedData into an unscaled feature vector.
    ///
    /// Converts parsed spacecraft data to a numeric feature vector using
    /// the preprocessing configuration (one-hot encoding, etc.) but without
    /// applying scaling.
    ///
    /// # Process
    ///
    /// 1. Initialize feature vector with zeros
    /// 2. Fill in numeric features from parsed data
    /// 3. Set one-hot encoded categorical features to 1 where appropriate
    /// 4. Handle missing values (filled with zero)
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed spacecraft data
    ///
    /// # Returns
    ///
    /// Feature vector with length equal to `n_features()`
    fn transform_unscaled(&self, data: &ParsedData) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
        let n_features = self.metadata.feature_columns.len();
        let mut features = vec![0.0; n_features];

        // Convert ParsedData to HashMap for efficient lookup
        let param_map: HashMap<String, &ParsedValue> = data.parameters
            .iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();

        for (idx, col_name) in self.metadata.feature_columns.iter().enumerate() {
            if self.metadata.numeric_columns.contains(col_name) {
                // Numeric column - use value directly
                if let Some(value) = param_map.get(col_name) {
                    features[idx] = match value {
                        ParsedValue::UInt(v) => *v as f64,
                        ParsedValue::Int(v) => *v as f64,
                        ParsedValue::Float(v) => *v,
                        _ => 0.0,
                    };
                }
                // If parameter is missing, leave as 0.0 (default)
            } else {
                // One-hot encoded categorical column
                // Column name format: "PARAM_VALUE" or "PARAM_Other"
                if let Some(underscore_pos) = col_name.rfind('_') {
                    let param_name = &col_name[..underscore_pos];
                    let encoded_value = &col_name[underscore_pos + 1..];

                    if let Some(actual_value) = param_map.get(param_name) {
                        // Convert actual value to string for comparison
                        let actual_str = match actual_value {
                            ParsedValue::String(s) | ParsedValue::State(s) => s.as_str(),
                            ParsedValue::UInt(v) => &v.to_string(),
                            ParsedValue::Int(v) => &v.to_string(),
                            ParsedValue::Float(v) => &v.to_string(),
                        };

                        if encoded_value == actual_str {
                            // Exact match - set this one-hot column to 1
                            features[idx] = 1.0;
                        } else if encoded_value == "Other" {
                            // Check if this is an unseen value
                            if let Some(valid_values) = self.metadata.categorical_valid_values.get(param_name) {
                                if !valid_values.contains(&actual_str.to_string()) {
                                    // Unseen value - set "Other" column to 1
                                    features[idx] = 1.0;
                                }
                            }
                        }
                    }
                    // If parameter is missing, leave all one-hot columns as 0.0
                }
            }
        }

        Ok(features)
    }

    /// Transform a single sample for inference (with scaling).
    ///
    /// Converts parsed data to a scaled feature vector ready for
    /// input to the ML model.
    ///
    /// # Arguments
    ///
    /// * `data` - Parsed spacecraft data
    ///
    /// # Returns
    ///
    /// Scaled feature vector as f32 (ONNX input format)
    pub fn transform(&self, data: &ParsedData) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
        // Get unscaled features
        let features = self.transform_unscaled(data)?;

        // Apply min-max scaling
        if let Some(scaler) = &self.scaler {
            let scaled: Vec<f32> = features
                .iter()
                .zip(scaler.min_.iter())
                .zip(scaler.scale_.iter())
                .map(|((x, min_val), scale_val)| {
                    // scaled = x * scale + min
                    ((x * scale_val) + min_val) as f32
                })
                .collect();
            Ok(scaled)
        } else {
            // No scaler fitted - return unscaled (shouldn't happen in production)
            Ok(features.iter().map(|&x| x as f32).collect())
        }
    }

    /// Transform a batch of samples for training (without scaling).
    ///
    /// Converts multiple parsed samples to feature vectors. Used during
    /// training to generate data for fitting the scaler.
    ///
    /// # Arguments
    ///
    /// * `data` - Collection of parsed spacecraft data
    ///
    /// # Returns
    ///
    /// Vector of unscaled feature vectors (f64 for precision during training)
    pub fn transform_batch(&self, data: &[ParsedData]) -> Result<Vec<Vec<f64>>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();
        
        for parsed_data in data.iter() {
            let features = self.transform_unscaled(parsed_data)?;
            results.push(features);
        }
        
        Ok(results)
    }

    /// Load a preprocessor from saved files.
    ///
    /// Reconstructs a preprocessor from metadata and scaler parameters
    /// saved during training. This ensures inference uses the same
    /// preprocessing as training.
    ///
    /// # Arguments
    ///
    /// * `model_dir` - Directory containing `metadata.json` and `scaler.json`
    ///
    /// # Returns
    ///
    /// Fully configured preprocessor ready for inference
    pub fn load(model_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        // Load metadata (contains preprocessing section)
        let metadata_path = model_dir.join("metadata.json");
        let metadata_str = fs::read_to_string(metadata_path)?;
        let full_metadata: serde_json::Value = serde_json::from_str(&metadata_str)?;
        
        let preprocessing_metadata: PreprocessingMetadata = 
            serde_json::from_value(full_metadata["preprocessing"].clone())?;

        // Load scaler parameters
        let scaler_path = model_dir.join("scaler.json");
        let scaler_str = fs::read_to_string(scaler_path)?;
        let scaler: ScalerData = serde_json::from_str(&scaler_str)?;

        Ok(Preprocessor {
            metadata: preprocessing_metadata,
            scaler: Some(scaler),
        })
    }

    /// Save preprocessor parameters to disk.
    ///
    /// Saves scaler parameters to `scaler.json`. The preprocessing metadata
    /// is saved as part of the full model metadata by the training pipeline.
    ///
    /// # Arguments
    ///
    /// * `model_dir` - Directory to save files to
    pub fn save(&self, model_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(model_dir)?;

        // Save scaler parameters
        if let Some(scaler) = &self.scaler {
            let scaler_path = model_dir.join("scaler.json");
            let scaler_json = serde_json::to_string_pretty(scaler)?;
            let mut file = File::create(scaler_path)?;
            file.write_all(scaler_json.as_bytes())?;
        }

        Ok(())
    }

    /// Save preprocessed training data as CSV.
    ///
    /// Exports feature vectors to CSV format for analysis or use with
    /// external tools (e.g., Python ML libraries).
    ///
    /// # Arguments
    ///
    /// * `data` - Preprocessed feature vectors
    /// * `output_path` - Path to output CSV file
    pub fn save_numpy_data(&self, data: &[Vec<f64>], output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if data.is_empty() {
            return Err("Cannot save empty data".into());
        }

        let mut file = File::create(output_path)?;
        
        // Write each feature vector as a CSV row
        for row in data {
            if row.is_empty() {
                continue;
            }
            let row_str: Vec<String> = row.iter().map(|x| x.to_string()).collect();
            writeln!(file, "{}", row_str.join(","))?;
        }

        Ok(())
    }

    /// Get the preprocessing metadata.
    pub fn get_metadata(&self) -> &PreprocessingMetadata {
        &self.metadata
    }

    /// Get the scaler parameters.
    pub fn get_scaler(&self) -> Option<&ScalerData> {
        self.scaler.as_ref()
    }

    /// Get the number of features in the feature vector.
    pub fn n_features(&self) -> usize {
        self.metadata.feature_columns.len()
    }
}