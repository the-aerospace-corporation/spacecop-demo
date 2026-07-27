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

//! Data Models for Spacecraft Command and Telemetry
//!
//! This module defines the data structures used throughout SpaceCop ML for
//! representing spacecraft commands, telemetry packets, and their parameters.
//!
//! # Structure Categories
//!
//! - **Database Models**: Direct mappings to SQLite database tables
//! - **Parsed Data Models**: Runtime representations of decoded packets
//! - **JSON Models**: Serializable formats for network transmission
//!
//! # Database Schema
//!
//! The database models correspond to a COSMOS-compatible schema with tables for:
//! - Commands and their parameters
//! - Telemetry packets and their items
//! - State definitions for enumerated values

use serde::{Serialize, Deserialize};

// ============================================================================
// Database structs
// ============================================================================

/// Spacecraft command definition from the database.
///
/// Represents a command that can be sent to a spacecraft system.
/// Commands are composed of multiple parameters that specify the command's data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Command {
    /// Unique database identifier
    pub id: i32,
    /// Spacecraft system name (e.g., "GUIDANCE", "POWER", "THERMAL")
    pub system: String,
    /// Command name (e.g., "SET_MODE", "ENABLE_HEATER")
    pub name: String,
    /// Human-readable description of the command's purpose
    pub description: Option<String>,
    /// Byte order: "BIG_ENDIAN" or "LITTLE_ENDIAN"
    pub endian: Option<String>,
}

/// Parameter definition for a spacecraft command.
///
/// Each command consists of one or more parameters that define the
/// binary structure and data types of the command packet.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CommandParameter {
    /// Unique database identifier
    pub id: i32,
    /// Foreign key to parent command
    pub command_id: i32,
    /// Parameter name (e.g., "MODE", "TEMPERATURE_SETPOINT")
    pub name: String,
    /// Size in bits (e.g., 8, 16, 32, 64)
    pub bit_length: Option<i32>,
    /// Data type (e.g., "UINT", "INT", "FLOAT", "STRING", "BLOCK")
    pub type_: Option<String>,
    /// Minimum valid value (for validation)
    pub min: Option<String>,
    /// Maximum valid value (for validation)
    pub max: Option<String>,
    /// Default value if not specified
    pub default_value: Option<String>,
    /// Human-readable description
    pub description: Option<String>,
    /// True if this parameter is an array
    pub is_array: bool,
    /// Number of elements if array
    pub array_length: Option<i32>,
    /// Format string for display (e.g., "0x%X", "%.2f")
    pub format_string: Option<String>,
    /// Byte order override for this parameter
    pub endianness: Option<String>,
}

/// State definition for enumerated command parameters.
///
/// Maps numeric values to human-readable state names
/// (e.g., 0 = "OFF", 1 = "ON", 2 = "STANDBY").
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CommandParameterState {
    /// Unique database identifier
    pub id: i32,
    /// Foreign key to parent parameter
    pub parameter_id: i32,
    /// Human-readable state name (e.g., "ENABLED", "DISABLED")
    pub state_name: Option<String>,
    /// Numeric value corresponding to this state
    pub state_value: Option<String>,
}

/// Telemetry packet definition from the database.
///
/// Represents a telemetry packet received from a spacecraft system.
/// Packets contain multiple items that encode sensor readings and status.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TelemetryPacket {
    /// Unique database identifier
    pub id: i32,
    /// Spacecraft system name (e.g., "GUIDANCE", "POWER", "THERMAL")
    pub system: String,
    /// Packet name (e.g., "HEALTH_STATUS", "SENSOR_DATA")
    pub name: String,
    /// Human-readable description of the packet's contents
    pub description: Option<String>,
    /// Byte order: "BIG_ENDIAN" or "LITTLE_ENDIAN"
    pub endian: Option<String>,
}

/// Telemetry item (field) within a telemetry packet.
///
/// Each telemetry packet consists of multiple items that define the
/// binary structure and data types of sensor readings and status fields.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TelemetryItem {
    /// Unique database identifier
    pub id: i32,
    /// Foreign key to parent telemetry packet
    pub packet_id: i32,
    /// Item name (e.g., "VOLTAGE", "TEMPERATURE", "STATUS")
    pub name: String,
    /// Size in bits (e.g., 8, 16, 32, 64)
    pub bit_length: Option<i32>,
    /// Data type (e.g., "UINT", "INT", "FLOAT", "STRING", "BLOCK")
    pub type_: Option<String>,
    /// Default value if not present
    pub default_value: Option<String>,
    /// Human-readable description
    pub description: Option<String>,
    /// True if this item is used for packet identification
    pub is_id_field: bool,
    /// Format string for display (e.g., "0x%X", "%.2f")
    pub format_string: Option<String>,
    /// Physical units name (e.g., "Volts", "Celsius")
    pub units_name: Option<String>,
    /// Units symbol (e.g., "V", "°C")
    pub units_symbol: Option<String>,
    /// Byte order override for this item
    pub endianness: Option<String>,
    /// Order of this item in the packet structure
    pub item_order: Option<i32>,
}

/// State definition for enumerated telemetry items.
///
/// Maps numeric values to human-readable state names for telemetry
/// (e.g., 0 = "NOMINAL", 1 = "WARNING", 2 = "ERROR").
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TelemetryState {
    /// Unique database identifier
    pub id: i32,
    /// Foreign key to parent telemetry item
    pub item_id: i32,
    /// Human-readable state name (e.g., "ACTIVE", "INACTIVE")
    pub state_name: String,
    /// Numeric value corresponding to this state
    pub state_value: String,
}

// ============================================================================
// Parameter trait for generic handling
// ============================================================================

/// Generic trait for accessing parameter/item properties.
///
/// Provides a unified interface for working with both command parameters
/// and telemetry items, enabling generic parsing and processing logic.
#[allow(dead_code)]
pub trait Parameter {
    /// Get the parameter/item name
    fn name(&self) -> &str;
    /// Get the size in bits
    fn bit_length(&self) -> i32;
    /// Get the data type (e.g., "UINT", "FLOAT")
    fn type_(&self) -> Option<&str>;
    /// Get the byte order
    fn endianness(&self) -> Option<&str>;
    /// Get the default value
    fn default_value(&self) -> Option<&str>;
    /// Get the description
    fn description(&self) -> Option<&str>;
}

/// Implementation of Parameter trait for command parameters
impl Parameter for CommandParameter {
    fn name(&self) -> &str { &self.name }
    fn bit_length(&self) -> i32 { self.bit_length.unwrap_or(0) }
    fn type_(&self) -> Option<&str> { self.type_.as_deref() }
    fn endianness(&self) -> Option<&str> { self.endianness.as_deref() }
    fn default_value(&self) -> Option<&str> { self.default_value.as_deref() }
    fn description(&self) -> Option<&str> { self.description.as_deref() }
}

/// Implementation of Parameter trait for telemetry items
impl Parameter for TelemetryItem {
    fn name(&self) -> &str { &self.name }
    fn bit_length(&self) -> i32 { self.bit_length.unwrap_or(0) }
    fn type_(&self) -> Option<&str> { self.type_.as_deref() }
    fn endianness(&self) -> Option<&str> { self.endianness.as_deref() }
    fn default_value(&self) -> Option<&str> { self.default_value.as_deref() }
    fn description(&self) -> Option<&str> { self.description.as_deref() }
}

// ============================================================================
// Parsed result structures
// ============================================================================

/// Runtime representation of parsed spacecraft data.
///
/// This structure represents a fully decoded command or telemetry packet
/// with all parameters/items converted to their appropriate data types.
/// Used internally for anomaly detection and processing.
#[derive(Debug, Clone)]
pub struct ParsedData {
    /// Type of data: "CMD" or "TLM"
    pub data_type: String,
    /// Spacecraft system name
    pub system: String,
    /// Command or packet name
    pub name: String,
    /// List of (parameter_name, value) tuples
    pub parameters: Vec<(String, ParsedValue)>,
}

/// Enumeration of possible parameter value types.
///
/// Represents the decoded value of a parameter or telemetry item
/// after binary parsing and type conversion.
#[derive(Debug, Clone)]
pub enum ParsedValue {
    /// Unsigned integer value (8, 16, 32, or 64 bits)
    UInt(u64),
    /// Signed integer value (8, 16, 32, or 64 bits)
    Int(i64),
    /// Floating-point value (32 or 64 bits)
    Float(f64),
    /// String value (ASCII or UTF-8)
    String(String),
    /// Enumerated state value (human-readable name)
    State(String),
}

// ============================================================================
// JSON-serializable output structures
// ============================================================================

/// JSON-serializable representation of parsed spacecraft data.
///
/// Used for network transmission and API responses. Includes type
/// information and formatted representations for each parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedDataJson {
    /// Type of data: "CMD" or "TLM"
    pub data_type: String,
    /// Spacecraft system name
    pub system: String,
    /// Command or packet name
    pub name: String,
    /// List of parameters with JSON-formatted values
    pub parameters: Vec<ParameterJson>,
}

/// JSON representation of a single parameter.
///
/// Wraps the parameter name and a JSON value object that includes
/// type information and multiple representations (decimal, hex, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterJson {
    /// Parameter or item name
    pub name: String,
    /// JSON object with type and value information
    pub value: serde_json::Value,
}

/// Conversion from internal ParsedData to JSON-serializable format.
///
/// Transforms each ParsedValue into a JSON object with:
/// - `type`: The data type ("uint", "int", "float", "string", "state")
/// - `value`: The actual value
/// - `hex`: Hexadecimal representation (for integers)
impl From<ParsedData> for ParsedDataJson {
    fn from(data: ParsedData) -> Self {
        let parameters = data.parameters.into_iter().map(|(name, value)| {
            // Convert each value to a structured JSON object
            let json_value = match value {
                ParsedValue::UInt(v) => serde_json::json!({
                    "type": "uint",
                    "value": v,
                    "hex": format!("0x{:X}", v)
                }),
                ParsedValue::Int(v) => serde_json::json!({
                    "type": "int",
                    "value": v
                }),
                ParsedValue::Float(v) => serde_json::json!({
                    "type": "float",
                    "value": v
                }),
                ParsedValue::String(v) => serde_json::json!({
                    "type": "string",
                    "value": v
                }),
                ParsedValue::State(v) => serde_json::json!({
                    "type": "state",
                    "value": v
                }),
            };
            ParameterJson {
                name,
                value: json_value,
            }
        }).collect();

        ParsedDataJson {
            data_type: data.data_type,
            system: data.system,
            name: data.name,
            parameters,
        }
    }
}