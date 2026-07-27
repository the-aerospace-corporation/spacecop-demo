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

//! Real-Time Inference Server with Multi-Layer Security Detection
//!
//! This module implements a TCP server that receives spacecraft command and
//! telemetry data as hex strings, performs multiple layers of security analysis,
//! and broadcasts alerts to SpaceCOP when threats are detected.
//!
//! # Detection Layers
//!
//! The server implements defense-in-depth with three detection mechanisms:
//!
//! ## 1. Pre-Parse Detection (Works on ALL packets)
//!
//! - **Replay Attack Detection**: Identifies duplicate packets within a time window
//! - **Command Flooding Detection**: Detects excessive command rates (DoS attacks)
//!
//! These checks run on raw hex strings before parsing, so they work even on
//! unknown packet types.
//!
//! ## 2. Post-Parse Detection (Works on recognized packets)
//!
//! - **ML Anomaly Detection**: Uses trained autoencoders to detect unusual patterns
//!
//! This requires successful parsing and a trained model for the packet type.
//!
//! # Network Architecture
//!
//! ```text
//! ┌─────────────┐                    ┌──────────────────┐
//! │  Data       │  Hex Strings       │  SpaceCop ML     │
//! │  Source     ├───────────────────>│  Server          │
//! │  (Port 9111)│                    │  (This module)   │
//! └─────────────┘                    └────────┬─────────┘
//!                                             │ Alerts (JSON)
//!                                             v
//!                                    ┌──────────────────┐
//!                                    │  SpaceCOP        │
//!                                    │  Dashboard       │
//!                                    │  (Port 9112)     │
//!                                    └──────────────────┘
//! ```
//!
//! # Alert Types (STIX Patterns)
//!
//! - `replay-attack`: Duplicate packet detected
//! - `command-flooding-attack`: Excessive command rate
//! - `unauthorized-command`: ML-detected anomaly
//!
//! # Configuration
//!
//! Default settings (adjust based on operational requirements):
//! - Rate limit: 50 commands per 60-second window
//! - Replay window: 30 seconds
//! - Alert cooldown: 30 seconds (prevents alert spam)

use std::net::{TcpListener, TcpStream};
use std::io::{BufRead, BufReader, Write};
use std::thread;
use std::sync::Arc;
use std::sync::Mutex;
use std::path::Path;
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use crate::parser::CmdTlmParser;
use crate::models::{ParsedDataJson, ParsedData};
use crate::anomaly_detector::AnomalyDetectionSystem;

/// Default port for receiving hex data from spacecraft systems
pub const INPUT_PORT: u16 = 9111;

/// Default port for sending alerts to SpaceCOP dashboard
pub const SPACECOP_ALERT_PORT: u16 = 9112;

/// Simple rate monitor for detecting command flooding attacks.
///
/// Tracks command rates based on APP ID (first 6 hex characters) and
/// detects when the rate exceeds a configured threshold within a sliding
/// time window.
///
/// This operates on raw hex strings, so it works even for unknown packet types.
pub struct SimpleRateMonitor {
    /// Map of APP ID to command timestamps
    command_history: HashMap<String, VecDeque<SystemTime>>,
    /// Sliding time window for rate calculation
    window_duration: Duration,
    /// Maximum commands allowed in the window
    max_commands_per_window: usize,
}

impl SimpleRateMonitor {
    /// Create a new rate monitor.
    ///
    /// # Arguments
    ///
    /// * `window_seconds` - Size of sliding time window (e.g., 60)
    /// * `max_commands` - Maximum commands allowed in window (e.g., 50)
    pub fn new(window_seconds: u64, max_commands: usize) -> Self {
        SimpleRateMonitor {
            command_history: HashMap::new(),
            window_duration: Duration::from_secs(window_seconds),
            max_commands_per_window: max_commands,
        }
    }

    /// Check if the command rate is suspicious.
    ///
    /// Extracts the APP ID from the hex string and checks if the rate
    /// for that APP ID exceeds the threshold.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Raw hex string (e.g., "18C8C00000010D00")
    ///
    /// # Returns
    ///
    /// Tuple of `(is_flooding, current_rate, threshold)`
    pub fn check_rate(&mut self, hex_str: &str) -> (bool, usize, usize) {
        // Extract APP ID from hex (first 6 characters)
        // Examples:
        //   18C8C00000010D00 -> 18C8C0
        //   08EAC114000E0000 -> 08EAC1
        let app_id = if hex_str.len() >= 6 {
            hex_str[..6].to_string()
        } else {
            hex_str.to_string()
        };

        let now = SystemTime::now();
        
        // Get or create history for this APP ID
        let history = self.command_history
            .entry(app_id)
            .or_insert_with(VecDeque::new);
        
        // Add current timestamp
        history.push_back(now);
        
        // Remove timestamps outside the sliding window
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

    /// Clean up old entries to prevent unbounded memory growth.
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
        
        self.command_history.retain(|_, history| !history.is_empty());
    }
}

/// Replay attack detector for identifying duplicate packets.
///
/// Maintains a hash-based cache of recently seen packets and flags
/// exact duplicates within a time window as potential replay attacks.
///
/// This operates on raw hex strings, so it works even for unknown packet types.
pub struct ReplayDetector {
    /// Map of packet hash to last seen timestamp
    seen_packets: HashMap<u64, SystemTime>,
    /// Time window for considering packets as replays
    window_duration: Duration,
}

impl ReplayDetector {
    /// Create a new replay detector.
    ///
    /// # Arguments
    ///
    /// * `window_seconds` - Time window for replay detection (e.g., 30)
    pub fn new(window_seconds: u64) -> Self {
        ReplayDetector {
            seen_packets: HashMap::new(),
            window_duration: Duration::from_secs(window_seconds),
        }
    }

    /// Check if this exact hex string was seen recently.
    ///
    /// Computes a hash of the hex string and checks if it was seen
    /// within the configured time window.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Raw hex string to check
    ///
    /// # Returns
    ///
    /// `true` if this is a likely replay attack, `false` otherwise
    pub fn is_replay(&mut self, hex_str: &str) -> bool {
        // Hash the entire hex string
        let mut hasher = DefaultHasher::new();
        hex_str.hash(&mut hasher);
        let hex_hash = hasher.finish();
        
        let now = SystemTime::now();
        
        if let Some(last_time) = self.seen_packets.get(&hex_hash) {
            if let Ok(elapsed) = now.duration_since(*last_time) {
                if elapsed < self.window_duration {
                    // Seen this exact packet within window - likely replay
                    return true;
                }
            }
        }
        
        // Record this packet for future checks
        self.seen_packets.insert(hex_hash, now);
        false
    }

    /// Clean up old entries to prevent unbounded memory growth.
    pub fn cleanup(&mut self) {
        let now = SystemTime::now();
        let cleanup_threshold = self.window_duration * 2;
        
        self.seen_packets.retain(|_, last_time| {
            if let Ok(elapsed) = now.duration_since(*last_time) {
                elapsed < cleanup_threshold
            } else {
                true
            }
        });
    }
}

/// Alert tracker to prevent duplicate alert spam.
///
/// Maintains cooldown periods for different alert types to avoid
/// overwhelming the SpaceCOP dashboard with repeated alerts for
/// the same issue.
pub struct SimpleAlertTracker {
    /// Map of alert key to last alert timestamp
    last_alerts: HashMap<String, SystemTime>,
    /// Minimum time between alerts for the same key
    cooldown_duration: Duration,
}

impl SimpleAlertTracker {
    /// Create a new alert tracker.
    ///
    /// # Arguments
    ///
    /// * `cooldown_seconds` - Minimum seconds between duplicate alerts (e.g., 30)
    pub fn new(cooldown_seconds: u64) -> Self {
        SimpleAlertTracker {
            last_alerts: HashMap::new(),
            cooldown_duration: Duration::from_secs(cooldown_seconds),
        }
    }

    /// Check if an alert should be sent.
    ///
    /// # Arguments
    ///
    /// * `alert_key` - Unique key for this alert type (e.g., "FLOODING_18C8")
    ///
    /// # Returns
    ///
    /// `true` if alert should be sent, `false` if still in cooldown
    pub fn should_alert(&mut self, alert_key: &str) -> bool {
        let now = SystemTime::now();
        
        if let Some(last_time) = self.last_alerts.get(alert_key) {
            if let Ok(elapsed) = now.duration_since(*last_time) {
                if elapsed < self.cooldown_duration {
                    return false; // Still in cooldown
                }
            }
        }
        
        // Update timestamp and allow alert
        self.last_alerts.insert(alert_key.to_string(), now);
        true
    }

    /// Clean up old entries to prevent unbounded memory growth.
    pub fn cleanup(&mut self) {
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

/// Real-time inference server with multi-layer security detection.
///
/// Listens for hex-encoded spacecraft data on one port and sends
/// security alerts to SpaceCOP on another port.
pub struct BroadcastServer {
    /// Parser for converting hex to structured data
    parser: Arc<CmdTlmParser>,
    /// ML-based anomaly detection system
    anomaly_system: Arc<AnomalyDetectionSystem>,
    /// Port for receiving hex data
    input_port: u16,
    /// Port for sending alerts to SpaceCOP
    spacecop_port: u16,
    /// Active connection to SpaceCOP dashboard
    spacecop_connection: Arc<Mutex<Option<TcpStream>>>,
    /// Rate monitor for flooding detection
    rate_monitor: Arc<Mutex<SimpleRateMonitor>>,
    /// Replay detector for duplicate packets
    replay_detector: Arc<Mutex<ReplayDetector>>,
    /// Alert tracker to prevent spam
    alert_tracker: Arc<Mutex<SimpleAlertTracker>>,
}

impl BroadcastServer {
    /// Create a new broadcast server.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to SQLite database with packet definitions
    /// * `models_dir` - Directory containing trained ML models
    /// * `input_port` - Port to listen for hex data (typically 9111)
    /// * `spacecop_port` - Port to send alerts to SpaceCOP (typically 9112)
    ///
    /// # Configuration
    ///
    /// Default security thresholds:
    /// - Rate limit: 50 commands per 60 seconds
    /// - Replay window: 30 seconds
    /// - Alert cooldown: 30 seconds
    ///
    /// Adjust these values based on your operational requirements.
    pub fn new(db_path: &str, models_dir: &Path, input_port: u16, spacecop_port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let anomaly_system = AnomalyDetectionSystem::new(models_dir)?;

        Ok(BroadcastServer {
            parser: Arc::new(CmdTlmParser::new(db_path)),
            anomaly_system: Arc::new(anomaly_system),
            input_port,
            spacecop_port,
            spacecop_connection: Arc::new(Mutex::new(None)),
            // Monitor 60-second windows, alert if >50 commands
            rate_monitor: Arc::new(Mutex::new(SimpleRateMonitor::new(60, 50))),
            // Detect replays within 30 seconds
            replay_detector: Arc::new(Mutex::new(ReplayDetector::new(30))),
            // Cooldown for flooding/replay alerts (30 seconds)
            alert_tracker: Arc::new(Mutex::new(SimpleAlertTracker::new(30))),
        })
    }

    /// Establish connection to SpaceCOP dashboard.
    ///
    /// Attempts to connect to SpaceCOP and sends a handshake message.
    /// The connection is maintained for sending alerts.
    fn connect_to_spacecop(&self) -> std::io::Result<()> {
        println!("Attempting to connect to SpaceCOP at localhost:{}", self.spacecop_port);

        match TcpStream::connect(format!("127.0.0.1:{}", self.spacecop_port)) {
            Ok(mut stream) => {
                println!("Successfully connected to SpaceCOP on port {}", self.spacecop_port);

                // Send connection handshake
                let handshake = serde_json::json!({
                    "status": "connected",
                    "message": "SpaceCOP ML Anomaly Detection System"
                });

                if let Ok(json) = serde_json::to_string(&handshake) {
                    writeln!(stream, "{}", json)?;
                    stream.flush()?;
                }

                let mut conn = self.spacecop_connection.lock().unwrap();
                *conn = Some(stream);
                Ok(())
            }
            Err(e) => {
                eprintln!("Failed to connect to SpaceCOP: {}", e);
                Err(e)
            }
        }
    }

    /// Send a JSON alert to SpaceCOP.
    ///
    /// Attempts to send the alert over the active connection. If the
    /// connection is lost, attempts to reconnect and retry.
    ///
    /// # Arguments
    ///
    /// * `json_str` - JSON-formatted alert message
    fn send_alert(&self, json_str: &str) -> std::io::Result<()> {
        let mut conn = self.spacecop_connection.lock().unwrap();

        match conn.as_mut() {
            Some(stream) => {
                match writeln!(stream, "{}", json_str) {
                    Ok(_) => {
                        // IMPORTANT: Flush to ensure data is sent immediately
                        if let Err(e) = stream.flush() {
                            eprintln!("Error flushing stream: {}", e);
                            *conn = None; // Clear the dead connection
                            return Err(e);
                        }
                        println!("  ⚠️  ALERT sent to SpaceCOP");
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error sending alert, connection may be lost: {}", e);
                        *conn = None; // Clear the dead connection
                        Err(e)
                    }
                }
            }
            None => {
                eprintln!("Not connected to SpaceCOP, attempting to reconnect...");
                drop(conn); // Release the lock before reconnecting

                if self.connect_to_spacecop().is_ok() {
                    // Try sending again after reconnecting
                    let mut conn = self.spacecop_connection.lock().unwrap();
                    if let Some(stream) = conn.as_mut() {
                        writeln!(stream, "{}", json_str)?;
                        stream.flush()?; // Flush after reconnect too
                        println!("  ⚠️  ALERT sent to SpaceCOP (after reconnect)");
                        return Ok(());
                    }
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "Unable to establish connection to SpaceCOP"
                ))
            }
        }
    }

    /// Start the server and begin processing data.
    ///
    /// This method blocks and runs the server loop, accepting connections
    /// and spawning threads to handle each client.
    pub fn start(&self) -> std::io::Result<()> {
        println!("Starting Hex Parser Broadcast Server with Anomaly Detection...");
        println!("  Input port (hex):  {}", self.input_port);
        println!("  SpaceCOP alert port: {}", self.spacecop_port);

        // Attempt initial connection to SpaceCOP
        let _ = self.connect_to_spacecop();

        // Start input server
        let input_listener = TcpListener::bind(format!("127.0.0.1:{}", self.input_port))?;
        println!("Hex input server listening on port {}", self.input_port);

        // Accept incoming connections
        for stream in input_listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Clone Arc references for the thread
                    let parser = Arc::clone(&self.parser);
                    let anomaly_system = Arc::clone(&self.anomaly_system);
                    let spacecop_connection = Arc::clone(&self.spacecop_connection);
                    let rate_monitor = Arc::clone(&self.rate_monitor);
                    let replay_detector = Arc::clone(&self.replay_detector);
                    let alert_tracker = Arc::clone(&self.alert_tracker);
                    let spacecop_port = self.spacecop_port;

                    // Spawn thread to handle this client
                    thread::spawn(move || {
                        let server_ref = BroadcastServer {
                            parser,
                            anomaly_system,
                            input_port: 0, // Not used in handler
                            spacecop_port,
                            spacecop_connection,
                            rate_monitor,
                            replay_detector,
                            alert_tracker,
                        };

                        if let Err(e) = Self::handle_input_client(stream, &server_ref) {
                            eprintln!("Error handling input client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting input connection: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single client connection.
    ///
    /// Reads hex strings line-by-line and performs multi-layer security analysis:
    /// 1. Pre-parse checks (replay, flooding) - work on all packets
    /// 2. Parse hex to structured data
    /// 3. Post-parse checks (ML anomaly) - work on recognized packets
    ///
    /// # Arguments
    ///
    /// * `stream` - TCP connection to the client
    /// * `server` - Server instance with shared state
    fn handle_input_client(
        stream: TcpStream,
        server: &BroadcastServer
    ) -> std::io::Result<()> {
        let peer_addr = stream.peer_addr()?;
        println!("Input client connected: {}", peer_addr);

        let reader = BufReader::new(stream);
        let mut processed_count = 0;

        for line in reader.lines() {
            match line {
                Ok(line_content) => {
                    let line_content = line_content.trim();
                    if line_content.is_empty() {
                        continue;
                    }

                    let hex_str = line_content.to_string();

                    println!("Received hex: {}", hex_str);

                    // ============================================================
                    // LAYER 1: PRE-PARSE CHECKS
                    // Work on ALL packets, even unknown ones
                    // ============================================================

                    // CHECK 1: Replay Detection (Commands Only)
                    {
                        // Determine if this is a command or telemetry
                        // Commands: first hex digit is 1 (e.g., 18C8C00000010D00)
                        // Telemetry: first hex digit is 0 (e.g., 08EAC114000E0000...)
                        let first_char = hex_str.chars().next().unwrap_or('0');
                        let is_command = first_char == '1';
                        
                        if is_command {
                            let mut replay_detector = server.replay_detector.lock().unwrap();
                            if replay_detector.is_replay(&hex_str) {
                                println!("  🚨 REPLAY ATTACK DETECTED: Exact packet seen recently");
                                
                                // Create alert key for deduplication
                                let alert_key = format!("REPLAY_{}", &hex_str[..std::cmp::min(16, hex_str.len())]);
                                let mut tracker = server.alert_tracker.lock().unwrap();
                                
                                if tracker.should_alert(&alert_key) {
                                    // Send alert to SpaceCOP
                                    let alert = serde_json::json!({
                                        "alert_type": "REPLAY_ATTACK",
                                        "stix_pattern": "replay-attack",
                                        "hex": hex_str,
                                        "description": "Duplicate packet detected - possible replay attack"
                                    });
                                    
                                    if let Ok(json_str) = serde_json::to_string(&alert) {
                                        if let Err(e) = server.send_alert(&json_str) {
                                            eprintln!("  Failed to send replay alert: {}", e);
                                        }
                                    }
                                } else {
                                    println!("  ⏸ Duplicate replay alert suppressed (within 30s)");
                                }
                            }
                        }
                    }

                    // CHECK 2: Rate/Flooding Detection (Commands Only)
                    {
                        // Determine if this is a command
                        let first_char = hex_str.chars().next().unwrap_or('0');
                        let is_command = first_char == '1';
                        
                        if is_command {
                            let mut rate_monitor = server.rate_monitor.lock().unwrap();
                            let (is_flooding, current_rate, threshold) = rate_monitor.check_rate(&hex_str);
                            
                            if is_flooding {
                                println!("  🚨 COMMAND FLOODING DETECTED: {} commands/min (threshold: {})", 
                                       current_rate, threshold);
                                
                                // Extract APP ID for alert key (first 6 characters)
                                let app_id = if hex_str.len() >= 4 {
                                    &hex_str[..4]
                                } else {
                                    &hex_str
                                };
                                
                                let alert_key = format!("FLOODING_{}", app_id);
                                let mut tracker = server.alert_tracker.lock().unwrap();
                                
                                if tracker.should_alert(&alert_key) {
                                    // Send alert to SpaceCOP
                                    let alert = serde_json::json!({
                                        "alert_type": "COMMAND_FLOODING",
                                        "stix_pattern": "command-flooding-attack",
                                        "app_id": app_id,
                                        "current_rate": current_rate,
                                        "threshold": threshold,
                                        "description": "Excessive command rate detected - possible DoS attack"
                                    });
                                    
                                    if let Ok(json_str) = serde_json::to_string(&alert) {
                                        if let Err(e) = server.send_alert(&json_str) {
                                            eprintln!("  Failed to send flooding alert: {}", e);
                                        }
                                    }
                                } else {
                                    println!("  ⏸ Duplicate flooding alert suppressed (within 30s)");
                                }
                            }
                        }
                    }

                    // ============================================================
                    // LAYER 2: PARSE HEX TO STRUCTURED DATA
                    // ============================================================

                    match server.parser.parse_hex(&hex_str) {
                        Ok(Some(parsed_data)) => {
                            println!("Parsed: {} - {}",
                                    parsed_data.system,
                                    parsed_data.name,
                            );

                            processed_count += 1;

                            // ========================================================
                            // LAYER 3: POST-PARSE CHECKS
                            // Work on recognized packets with trained models
                            // ========================================================

                            // CHECK 3: ML Anomaly Detection
                            let anomaly_result = server.anomaly_system.predict(&parsed_data);

                            match anomaly_result {
                                Ok(result) => {
                                    println!("  ML Anomaly: {}, MSE: {:.6}, Threshold: {:.6}",
                                            result.is_anomaly, result.mse, result.threshold);

                                    if result.is_anomaly {
                                        // Check if we should alert (deduplication)
                                        if server.anomaly_system.should_alert(&parsed_data) {
                                            let json_data: ParsedDataJson = parsed_data.clone().into();

                                            // Send alert to SpaceCOP
                                            let output_json = serde_json::json!({
                                                "alert_type": "ML_ANOMALY",
                                                "stix_pattern": "unauthorized-command",
                                                "severity": "MEDIUM",
                                                "data": json_data,
                                                "anomaly_detection": {
                                                    "is_anomaly": true,
                                                    "mse": result.mse,
                                                    "threshold": result.threshold,
                                                    "responsible_feature": result.responsible_feature,
                                                }
                                            });

                                            match serde_json::to_string(&output_json) {
                                                Ok(json_str) => {
                                                    if let Err(e) = server.send_alert(&json_str) {
                                                        eprintln!("  Failed to send ML alert: {}", e);
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("  Error serializing to JSON: {}", e);
                                                }
                                            }
                                        } else {
                                            println!("  ⏸ Duplicate ML anomaly suppressed (same data within 30s)");
                                        }
                                    } else {
                                        println!("  ✓ ML: Normal");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("  ML anomaly detection error: {}", e);
                                }
                            }
                        }
                        Ok(None) => {
                            println!("  ⚠️  Unknown packet (no parser match) - but still checked for flooding/replay");
                        }
                        Err(e) => {
                            eprintln!("  Error parsing hex '{}': {:?}", hex_str, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from input client: {}", e);
                    break;
                }
            }
        }

        println!("Input client disconnected: {} (processed {} commands)", peer_addr, processed_count);
        Ok(())
    }
}

/// Print parsed data in a human-readable format.
///
/// Utility function for displaying parsed spacecraft data to the console.
///
/// # Arguments
///
/// * `data` - Parsed command or telemetry data
pub fn print_parsed_data(data: &ParsedData) {
    use crate::models::ParsedValue;
    
    println!("Type: {}", data.data_type);
    println!("System: {}", data.system);
    println!("Name: {}", data.name);
    println!("Parameters:");
    for (name, value) in &data.parameters {
        match value {
            ParsedValue::UInt(v) => println!("  {}: {} (0x{:X})", name, v, v),
            ParsedValue::Int(v) => println!("  {}: {}", name, v),
            ParsedValue::Float(v) => println!("  {}: {}", name, v),
            ParsedValue::String(v) => println!("  {}: {}", name, v),
            ParsedValue::State(v) => println!("  {}: {}", name, v),
        }
    }
}