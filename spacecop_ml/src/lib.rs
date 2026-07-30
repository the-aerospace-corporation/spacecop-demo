// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

//! SpaceCop Machine Learning Library
//!
//! A comprehensive machine learning system for detecting anomalies in spacecraft
//! command and telemetry data using autoencoder neural networks.
//!
//! # Overview
//!
//! SpaceCop ML provides end-to-end capabilities for:
//! - Parsing binary spacecraft data packets
//! - Training anomaly detection models
//! - Real-time inference and alerting
//! - Command rate monitoring and attack detection
//!
//! # Architecture
//!
//! The library is organized into several key modules:
//!
//! ## Core Modules
//!
//! - **`models`**: Data structures for parsed spacecraft data
//! - **`parser`**: Hex string parser for CMD/TLM packets
//! - **`server`**: Real-time inference server with UDP broadcasting
//! - **`anomaly_detector`**: ML-based anomaly detection using autoencoders
//! - **`preprocessing`**: Feature engineering and data normalization
//! - **`training`**: Training pipeline for model development
//!
//! # Usage Examples
//!
//! ## Parsing Spacecraft Data
//!
//! ```no_run
//! use spacecop_ml::CmdTlmParser;
//!
//! let parser = CmdTlmParser::new("cmd_tlm.sqlite");
//! if let Ok(Some(data)) = parser.parse_hex("0x1992c00000040300020500") {
//!     println!("Parsed: {} {} {}", data.data_type, data.system, data.name);
//! }
//! ```
//!
//! ## Training Models
//!
//! ```no_run
//! use spacecop_ml::TrainingPipeline;
//!
//! let pipeline = TrainingPipeline::new("cmd_tlm.sqlite", "scml_models");
//! pipeline.train_from_file("training_data.txt")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Running Inference Server
//!
//! ```no_run
//! use spacecop_ml::{BroadcastServer, INPUT_PORT, SPACECOP_ALERT_PORT};
//! use std::path::Path;
//!
//! let server = BroadcastServer::new(
//!     "cmd_tlm.sqlite",
//!     Path::new("scml_models"),
//!     INPUT_PORT,
//!     SPACECOP_ALERT_PORT
//! )?;
//! server.start()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Anomaly Detection
//!
//! ```no_run
//! use spacecop_ml::AnomalyDetectionSystem;
//! use std::path::Path;
//!
//! let detector = AnomalyDetectionSystem::new(Path::new("scml_models"))?;
//! // Use with parsed data...
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Model Training Workflow
//!
//! 1. **Data Collection**: Gather normal operational data in hex format
//! 2. **Training**: Run `spacecop_ml train <data_file>` to train models
//! 3. **Model Export**: Models are automatically exported to ONNX format
//! 4. **Deployment**: Start inference server with trained models
//!
//! # Anomaly Detection Method
//!
//! SpaceCop uses autoencoder neural networks that learn to reconstruct normal
//! spacecraft data. Anomalies are detected when reconstruction error (MSE)
//! exceeds a threshold calculated during training:
//!
//! - **Normal Data**: Low reconstruction error (model has seen similar patterns)
//! - **Anomalous Data**: High reconstruction error (unusual patterns)
//!
//! # Security Features
//!
//! - **Anomaly Detection**: ML-based detection of unusual command/telemetry patterns
//! - **Rate Monitoring**: Detects command flooding attacks
//! - **Alert Deduplication**: Prevents alert spam with configurable cooldowns
//! - **Per-System Models**: Separate models for each spacecraft subsystem
//!
//! # Database Schema
//!
//! The system expects a SQLite database with spacecraft packet definitions
//! compatible with COSMOS (Ball Aerospace COSMOS format). The database should
//! contain tables defining:
//! - Packet structures (CMD/TLM)
//! - Parameter definitions
//! - Data types and formats

// Module declarations
/// Data models for parsed spacecraft commands and telemetry
pub mod models;

/// Parser for converting hex strings to structured spacecraft data
pub mod parser;

/// Real-time inference server with UDP alert broadcasting
pub mod server;

/// Machine learning-based anomaly detection system
pub mod anomaly_detector;

/// Feature engineering and data preprocessing for ML models
pub mod preprocessing;

/// Training pipeline for developing anomaly detection models
pub mod training;

// Public re-exports for convenient access to key types

/// Re-export all data models (ParsedData, ParsedValue, etc.)
pub use models::*;

/// Re-export the command/telemetry parser
pub use parser::CmdTlmParser;

/// Re-export server components and network port constants
pub use server::{BroadcastServer, INPUT_PORT, SPACECOP_ALERT_PORT};

/// Re-export anomaly detection system and result types
pub use anomaly_detector::{AnomalyDetectionSystem, AnomalyResult};

/// Re-export preprocessing components for feature engineering
pub use preprocessing::{Preprocessor, PreprocessingMetadata, ScalerData};

/// Re-export training pipeline for model development
pub use training::TrainingPipeline;