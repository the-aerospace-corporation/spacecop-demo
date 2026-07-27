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

//! SpaceCop ML - Main Entry Point
//!
//! This is the main executable for the SpaceCop machine learning system, which provides
//! anomaly detection for spacecraft command and telemetry data.
//!
//! # Modes of Operation
//!
//! - **Server Mode**: Runs the inference server with real-time anomaly detection
//! - **Training Mode**: Trains ML models from hex data files
//! - **Test Mode**: Runs built-in test cases for validation
//!
//! # Usage
//!
//! ```bash
//! # Run inference server
//! spacecop_ml server
//!
//! # Train models from data file
//! spacecop_ml train data/training_cmd.txt
//!
//! # Run test cases
//! spacecop_ml
//! ```

use spacecop_ml::{CmdTlmParser, BroadcastServer, INPUT_PORT, SPACECOP_ALERT_PORT};
use spacecop_ml::server::print_parsed_data;
use spacecop_ml::training::TrainingPipeline;
use rusqlite::Result;
use std::path::Path;

/// Main entry point for the SpaceCop ML application.
///
/// Parses command line arguments and dispatches to the appropriate mode:
/// - `server`: Starts the anomaly detection server
/// - `train <file>`: Trains ML models from the specified hex data file
/// - No arguments: Runs test cases for validation
///
/// # Returns
///
/// Returns `Ok(())` on success, or a `rusqlite::Result` error on database failures.
fn main() -> Result<()> {
    // Database path for storing command and telemetry data
    let db_path = "instance/cmd_tlm.sqlite";
    
    println!("Using database at: {}", db_path);

    // Directory where trained models are stored in ONNX format
    let models_dir = Path::new("scml_models");

    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 {
        match args[1].as_str() {
            "server" => {
                // Start the server with anomaly detection
                // The server listens for incoming telemetry and broadcasts alerts
                match BroadcastServer::new(db_path, models_dir, INPUT_PORT, SPACECOP_ALERT_PORT) {
                    Ok(server) => {
                        server.start().expect("Failed to start server");
                    }
                    Err(e) => {
                        eprintln!("Failed to initialize server: {}", e);
                        eprintln!("Make sure models are trained and exported to ONNX format");
                        std::process::exit(1);
                    }
                }
            }
            "train" => {
                // Training mode: train ML models from hex data file
                if args.len() < 3 {
                    eprintln!("Usage: {} train <training_file>", args[0]);
                    eprintln!("Example: {} train data/training_cmd.txt", args[0]);
                    std::process::exit(1);
                }
                
                let training_file = &args[2];
                
                // Validate that the training file exists before proceeding
                if !std::path::Path::new(training_file).exists() {
                    eprintln!("Error: Training file not found: {}", training_file);
                    std::process::exit(1);
                }
                
                // Initialize and run the training pipeline
                let pipeline = TrainingPipeline::new(db_path, "scml_models");
                match pipeline.train_from_file(training_file) {
                    Ok(()) => {
                        println!("\n✓ Training completed successfully!");
                    }
                    Err(e) => {
                        eprintln!("\n✗ Training failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                // Unknown command - print usage information
                eprintln!("Unknown command: {}", args[1]);
                eprintln!("Usage:");
                eprintln!("  {} server              - Run inference server", args[0]);
                eprintln!("  {} train <file>        - Train models from hex data file", args[0]);
                eprintln!("  {}                     - Run test cases", args[0]);
                std::process::exit(1);
            }
        }
    } else {
        // No arguments provided - run test cases for validation
        run_test_cases(db_path)?;
    }

    Ok(())
}

/// Runs built-in test cases to validate the command/telemetry parser.
///
/// This function executes three test cases with sample hex data to verify
/// that the parser correctly decodes spacecraft command and telemetry packets.
///
/// # Arguments
///
/// * `db_path` - Path to the SQLite database containing packet definitions
///
/// # Returns
///
/// Returns `Ok(())` on success, or a `rusqlite::Result` error on database failures.
///
/// # Test Cases
///
/// - **Test Case 1**: Large telemetry packet with floating-point data
/// - **Test Case 2**: Short command packet
/// - **Test Case 3**: Error report packet with ASCII string data
fn run_test_cases(db_path: &str) -> Result<()> {
    let parser = CmdTlmParser::new(db_path);

    // Test Case 1: Large telemetry packet with multiple floating-point values
    println!("=== Test Case 1 ===");
    if let Ok(Some(res)) = parser.parse_hex("0x0941e33902a500000387ab8500000000000000000000000000000000000000000000000000000000000000000000f03f00000000000000000000000000000000000000000000000000000000000000001b0de02d90a0e6bf00000000000000001b0de02d90a0e63f00000000000000000000000000000000000000000000000000000000000000f03f00000000000000000000000000000000fca9f1d24d62503f000000000000f03f000000000000f0bf00000000000000000000000000000000fca9f1d24d62503f00000000000000000000000000000000000000000000f03f0000000000000000fca9f1d24d62503ffca9f1d24d62503f0000000000000000000000000000f0bf0000000000000000fca9f1d24d62503f000000000000000000000000000000000000000000000000000000000000f03ffca9f1d24d62503f000000000000000000000000000000000000000000000000000000000000f0bffca9f1d24d62503ffca9f1d24d62503f01b14021e7fdffef3f800611c04c62503f800611c04c6250bf000000000000e03f000000000000e0bf000000000000e03f000000000000e0bf000000000000e03f000000000000f03f000000000000f83f01000000002c63a1bf00000000008b4fbf00000000008b4f3f000000209899d9bf000000209899d9bf00000020cbccdc3f000000000000f03f000000000000000000000000000000000000000000000000000000000000f03f000000000000000000000000000000000000000000000000000000000000f03f624a24d1cb28863f624a24d1cb28863f624a24d1cb28863f43c5387f130a31bf2d431cebe2363abfa94d9cdcef50443f000000000000000000000000000000000000000000000000000000000000f03f000000000000000000000000000000000000000000000000000000000000000000") {
        print_parsed_data(&res);
    }

    // Test Case 2: Short command packet
    println!("\n=== Test Case 2 ===");
    if let Ok(Some(res)) = parser.parse_hex("1992c00000040300020500") {
        print_parsed_data(&res);
    }

    // Test Case 3: Error report packet containing ASCII string data
    println!("\n=== Test Case 3 ===");
    if let Ok(Some(res)) = parser.parse_hex("0808c07800a5000003c430a3000000004e41560000000000000000000000000000000000200003002a000000010000004e4f564154454c5f4f454d3631353a2052657175657374206465766963652064617461207265706f72746564206572726f72202d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") {
        print_parsed_data(&res);
    }

    Ok(())
}