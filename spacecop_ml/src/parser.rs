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

//! Command and Telemetry Parser
//!
//! This module provides parsing capabilities for spacecraft command and telemetry
//! data encoded as hexadecimal strings. It uses a SQLite database containing
//! packet definitions to decode binary data into structured formats.
//!
//! # Parsing Process
//!
//! 1. **Identification**: Determine if data is CMD or TLM based on APP ID prefix
//! 2. **Lookup**: Query database for packet definition matching APP ID
//! 3. **Validation**: For commands, verify function code matches
//! 4. **Decoding**: Extract and parse each parameter/item based on bit positions
//! 5. **Type Conversion**: Convert binary data to appropriate types (int, float, string, state)
//!
//! # Packet Structure
//!
//! ## Command Packets (APP ID starts with '1')
//! - CCSDS Header (64 bits): APP ID, sequence, length, function code
//! - Payload: Command-specific parameters
//!
//! ## Telemetry Packets (APP ID starts with '0')
//! - CCSDS Header (128 bits): APP ID, sequence, length, timestamp
//! - Payload: Telemetry-specific items
//!
//! # Supported Data Types
//!
//! - **UINT**: Unsigned integers (8, 16, 32, 64 bits)
//! - **INT**: Signed integers (8, 16, 32, 64 bits)
//! - **FLOAT**: Floating-point (32, 64 bits)
//! - **STRING**: ASCII/UTF-8 strings
//! - **BLOCK**: Binary data blocks
//! - **STATE**: Enumerated values with named states

use rusqlite::{Connection, Result, params};
use std::collections::HashSet;
use crate::models::*;

/// Parser for spacecraft command and telemetry hex data.
///
/// Maintains a connection to a SQLite database containing packet definitions
/// and provides methods to parse hex strings into structured data.
pub struct CmdTlmParser {
    /// Path to the SQLite database with packet definitions
    db_path: String,
    /// Set of APP ID prefixes to ignore (e.g., fill patterns, invalid IDs)
    ignored: HashSet<String>,
}

impl CmdTlmParser {
    /// Create a new parser with the specified database.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to SQLite database containing COSMOS packet definitions
    ///
    /// # Ignored APP IDs
    ///
    /// The following APP ID prefixes are automatically ignored:
    /// - `DEAD`: Common fill pattern
    /// - `18C8`, `08FE`, `08FD`: Known invalid or test patterns
    pub fn new(db_path: &str) -> Self {
        let mut ignored = HashSet::new();
        // Add common fill patterns and invalid APP IDs
        ignored.insert("DEAD".to_string());
        ignored.insert("18C8".to_string());
        ignored.insert("08FE".to_string());
        ignored.insert("08FD".to_string());

        CmdTlmParser {
            db_path: db_path.to_string(),
            ignored,
        }
    }

    /// Parse a hexadecimal string into structured command or telemetry data.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Hex string with optional "0x" prefix (e.g., "0x1992c00000040300020500")
    ///
    /// # Returns
    ///
    /// - `Ok(Some(ParsedData))`: Successfully parsed data
    /// - `Ok(None)`: Data was ignored or couldn't be parsed
    /// - `Err`: Database error
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use spacecop_ml::CmdTlmParser;
    /// let parser = CmdTlmParser::new("cmd_tlm.sqlite");
    /// if let Ok(Some(data)) = parser.parse_hex("0x1992c00000040300020500") {
    ///     println!("Parsed {} {}", data.data_type, data.name);
    /// }
    /// ```
    pub fn parse_hex(&self, hex_str: &str) -> Result<Option<ParsedData>> {
        // Validate and clean hex string
        let hex_str = hex_str.trim();
        if hex_str.is_empty() {
            println!("Error: Empty hex string");
            return Ok(None);
        }

        // Normalize to uppercase with "0x" prefix
        let cleaned = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
            format!("0x{}", hex_str[2..].to_uppercase())
        } else {
            format!("0x{}", hex_str.to_uppercase())
        };

        // Minimum length check (need at least APP ID)
        if cleaned.len() < 6 {
            println!("Error: Hex string is not long enough: {}", cleaned);
            return Ok(None);
        }

        // Check if this APP ID should be ignored
        let app_id_prefix = &cleaned[2..6];
        if self.ignored.contains(app_id_prefix) {
            return Ok(None);
        }

        // Determine data type based on first hex digit after "0x"
        // '0' = Telemetry, '1' = Command
        let first_char = cleaned.chars().nth(2).unwrap();
        match first_char {
            '0' => self.parse_tlm(&cleaned),
            '1' => self.parse_cmd(&cleaned),
            _ => {
                println!("Error: Hex not identified as CMD or TLM: {}", cleaned);
                Ok(None)
            }
        }
    }

    /// Parse a command packet.
    ///
    /// # Process
    ///
    /// 1. Extract APP ID from hex string
    /// 2. Query database for commands with matching APP ID
    /// 3. Verify function code to identify specific command
    /// 4. Parse command parameters starting after CCSDS header
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Normalized hex string starting with "0x1..."
    fn parse_cmd(&self, hex_str: &str) -> Result<Option<ParsedData>> {
        let conn = Connection::open(&self.db_path)?;
        let app_id = &hex_str[..6]; // Extract "0x1XXX"

        // Get all commands with this APP ID
        // APP ID is stored as default_value in the first parameter
        let mut stmt = conn.prepare(
            "SELECT c.id, c.system, c.name, c.description, c.endian \
             FROM commands c \
             JOIN command_parameters cp ON c.id = cp.command_id \
             WHERE cp.default_value = ?"
        )?;

        let commands: Vec<Command> = stmt.query_map(params![app_id], |row| {
            Ok(Command {
                id: row.get(0)?,
                system: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                endian: row.get(4)?,
            })
        })?.collect::<Result<Vec<_>>>()?;

        if commands.is_empty() {
            println!("Error: No CMDs found fitting this APP ID. Hex: {}", hex_str);
            return Ok(None);
        }

        // Find the correct command by matching function code
        // Multiple commands may share the same APP ID but have different function codes
        let mut matched_command: Option<Command> = None;
        for cmd in &commands {
            if self.match_fc(&conn, cmd, hex_str)? {
                matched_command = Some(cmd.clone());
                break;
            }
        }

        let command = match matched_command {
            Some(cmd) => cmd,
            None => {
                println!("Error: No CMD found fitting this function code. Hex: {}", hex_str);
                return Ok(None);
            }
        };

        // Get all parameters for this command
        let parameters = self.get_command_parameters(&conn, command.id)?;

        // Parse payload parameters (skip CCSDS header - first 5 params)
        // CCSDS header: APP_ID, SEQUENCE, LENGTH, CHECKSUM, FUNCTION_CODE
        let bit_offset = 64; // Start after 64-bit header
        let params_to_parse = if parameters.len() > 5 {
            &parameters[5..]
        } else {
            &[]
        };

        let mut parsed_params = self.parse_parameters(hex_str, params_to_parse, bit_offset, &conn)?;

        // Include command name as a special parameter for ML features
        // System is not included since models are system-specific
        parsed_params.insert(0, ("_cmd_name".to_string(), ParsedValue::String(command.name.clone())));

        Ok(Some(ParsedData {
            data_type: "CMD".to_string(),
            system: command.system,
            name: command.name,
            parameters: parsed_params,
        }))
    }

    /// Match function code to identify the correct command.
    ///
    /// When multiple commands share the same APP ID, the function code
    /// (4th parameter) is used to distinguish between them.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `command` - Command to check
    /// * `hex_str` - Hex string containing the function code
    ///
    /// # Returns
    ///
    /// `true` if the function code in hex_str matches the command's expected value
    fn match_fc(&self, conn: &Connection, command: &Command, hex_str: &str) -> Result<bool> {
        // Get the 4th parameter (index 3) which should be the function code
        let mut stmt = conn.prepare(
            "SELECT bit_length, default_value, description \
             FROM command_parameters \
             WHERE command_id = ? \
             ORDER BY id \
             LIMIT 1 OFFSET 3"
        )?;

        let mut rows = stmt.query(params![command.id])?;
        
        if let Some(row) = rows.next()? {
            let bit_length: i32 = row.get(0)?;
            let default_value: Option<String> = row.get(1)?;

            // Calculate bit offset by summing lengths of first 3 parameters
            let mut stmt2 = conn.prepare(
                "SELECT bit_length FROM command_parameters \
                 WHERE command_id = ? \
                 ORDER BY id \
                 LIMIT 3"
            )?;

            let bit_lengths: Vec<i32> = stmt2.query_map(params![command.id], |row| {
                row.get(0)
            })?.collect::<Result<Vec<_>>>()?;

            // Convert bit offset to hex character position (4 bits per hex char)
            let char_shift = 2 + bit_lengths.iter().sum::<i32>() / 4;
            let length = bit_length / 4;

            // Compare expected function code with actual value in hex string
            if let Some(dv_str) = default_value {
                match (
                    u64::from_str_radix(dv_str.trim_start_matches("0x"), 16),
                    u64::from_str_radix(&hex_str[char_shift as usize..(char_shift + length) as usize], 16)
                ) {
                    (Ok(dv), Ok(hv)) => return Ok(dv == hv),
                    _ => return Ok(false),
                }
            }
        }

        Ok(false)
    }

    /// Parse a telemetry packet.
    ///
    /// # Process
    ///
    /// 1. Extract APP ID from hex string
    /// 2. Query database for telemetry packet with matching APP ID
    /// 3. Parse telemetry items starting after CCSDS header
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Normalized hex string starting with "0x0..."
    fn parse_tlm(&self, hex_str: &str) -> Result<Option<ParsedData>> {
        let conn = Connection::open(&self.db_path)?;
        let app_id = &hex_str[..6]; // Extract "0x0XXX"

        // Get telemetry packet with this APP ID
        // APP ID is stored as default_value in the first item
        let mut stmt = conn.prepare(
            "SELECT p.id, p.system, p.name, p.description, p.endian \
             FROM telemetry_packets p \
             JOIN telemetry_items ti ON p.id = ti.packet_id \
             WHERE ti.default_value = ?"
        )?;

        let packets: Vec<TelemetryPacket> = stmt.query_map(params![app_id], |row| {
            Ok(TelemetryPacket {
                id: row.get(0)?,
                system: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                endian: row.get(4)?,
            })
        })?.collect::<Result<Vec<_>>>()?;

        if packets.is_empty() {
            println!("Error: No TLMs found fitting this APP ID. Hex: {}", hex_str);
            return Ok(None);
        }

        let packet = &packets[0];

        // Get all items for this packet
        let items = self.get_telemetry_items(&conn, packet.id)?;

        // Parse items starting after TLM header (128 bits)
        // TLM header: APP_ID, SEQUENCE, LENGTH, SECONDS, SUBSECONDS, etc.
        let bit_offset = 128; // Start after 128-bit header
        let items_to_parse = if items.len() > 6 {
            &items[6..]
        } else {
            &[]
        };

        let mut parsed_params = self.parse_telemetry_items(hex_str, items_to_parse, bit_offset, &conn)?;

        // Include telemetry name as a special parameter for ML features
        // System is not included since models are system-specific
        parsed_params.insert(0, ("_tlm_name".to_string(), ParsedValue::String(packet.name.clone())));

        Ok(Some(ParsedData {
            data_type: "TLM".to_string(),
            system: packet.system.clone(),
            name: packet.name.clone(),
            parameters: parsed_params,
        }))
    }

    /// Parse command parameters from hex data.
    ///
    /// Iterates through parameter definitions, extracting and parsing
    /// each value from the hex string based on bit positions and types.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Full hex string
    /// * `parameters` - Parameter definitions to parse
    /// * `initial_bit_offset` - Starting bit position (after header)
    /// * `conn` - Database connection for state lookups
    fn parse_parameters(
        &self,
        hex_str: &str,
        parameters: &[CommandParameter],
        initial_bit_offset: i32,
        conn: &Connection,
    ) -> Result<Vec<(String, ParsedValue)>> {
        let hex_data = &hex_str[2..]; // Remove "0x" prefix
        let mut bit_offset = initial_bit_offset as usize;
        let mut results = Vec::new();

        for param in parameters {
            let bit_length = param.bit_length() as usize;
            
            // Check if this parameter has state definitions (enumerated values)
            let states = self.get_command_parameter_states(conn, param.id)?;

            let value = if !states.is_empty() {
                // Try to match to a state name
                let bits = self.extract_bits_from_hex(hex_data, bit_offset, bit_length.min(128))?;
                match self.match_state_cmd(&states, bits) {
                    Some(state_name) => ParsedValue::State(state_name),
                    None => {
                        // No matching state, parse as raw value
                        self.parse_parameter_value_from_hex(hex_data, bit_offset, bit_length, param)?
                    }
                }
            } else {
                // No states defined, parse as raw value
                self.parse_parameter_value_from_hex(hex_data, bit_offset, bit_length, param)?
            };

            results.push((param.name.clone(), value));
            bit_offset += bit_length;
        }

        Ok(results)
    }

    /// Parse telemetry items from hex data.
    ///
    /// Similar to parse_parameters but for telemetry items.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Full hex string
    /// * `items` - Item definitions to parse
    /// * `initial_bit_offset` - Starting bit position (after header)
    /// * `conn` - Database connection for state lookups
    fn parse_telemetry_items(
        &self,
        hex_str: &str,
        items: &[TelemetryItem],
        initial_bit_offset: i32,
        conn: &Connection,
    ) -> Result<Vec<(String, ParsedValue)>> {
        let hex_data = &hex_str[2..]; // Remove "0x" prefix
        let mut bit_offset = initial_bit_offset as usize;
        let mut results = Vec::new();

        for item in items {
            let bit_length = item.bit_length() as usize;
            
            // Check if this item has state definitions (enumerated values)
            let states = self.get_telemetry_states(conn, item.id)?;

            let value = if !states.is_empty() {
                // Try to match to a state name
                let bits = self.extract_bits_from_hex(hex_data, bit_offset, bit_length.min(128))?;
                match self.match_state_tlm(&states, bits) {
                    Some(state_name) => ParsedValue::State(state_name),
                    None => {
                        // No matching state, parse as raw value
                        self.parse_telemetry_value_from_hex(hex_data, bit_offset, bit_length, item)?
                    }
                }
            } else {
                // No states defined, parse as raw value
                self.parse_telemetry_value_from_hex(hex_data, bit_offset, bit_length, item)?
            };

            results.push((item.name.clone(), value));
            bit_offset += bit_length;
        }

        Ok(results)
    }

    /// Parse a command parameter value from hex data.
    ///
    /// Handles type-specific parsing including strings, integers, floats, etc.
    fn parse_parameter_value_from_hex(&self, hex_data: &str, bit_offset: usize, bit_length: usize, param: &CommandParameter) -> Result<ParsedValue> {
        let type_ = param.type_().unwrap_or("UINT");
        let endianness = param.endianness().unwrap_or("BIG_ENDIAN");
        
        if type_ == "STRING" {
            let s = self.extract_string_from_hex(hex_data, bit_offset, bit_length)?;
            Ok(ParsedValue::String(s))
        } else {
            let bits = self.extract_bits_from_hex(hex_data, bit_offset, bit_length)?;
            self.parse_value(bits, type_, bit_length, endianness)
        }
    }

    /// Parse a telemetry item value from hex data.
    ///
    /// Handles type-specific parsing including BLOCK types which are
    /// treated specially in telemetry.
    fn parse_telemetry_value_from_hex(&self, hex_data: &str, bit_offset: usize, bit_length: usize, item: &TelemetryItem) -> Result<ParsedValue> {
        let type_ = item.type_().unwrap_or("UINT");
        let endianness = item.endianness().unwrap_or("BIG_ENDIAN");
        
        if type_ == "STRING" {
            let s = self.extract_string_from_hex(hex_data, bit_offset, bit_length)?;
            Ok(ParsedValue::String(s))
        } else if type_ == "BLOCK" {
            // BLOCK types are opaque binary data, just record the size
            Ok(ParsedValue::String(format!("<BLOCK {} bits>", bit_length)))
        } else {
            let bits = self.extract_bits_from_hex(hex_data, bit_offset, bit_length)?;
            self.parse_value(bits, type_, bit_length, endianness)
        }
    }

    /// Parse a raw bit value into the appropriate data type.
    ///
    /// Handles endianness conversion and type-specific interpretation.
    ///
    /// # Arguments
    ///
    /// * `bits` - Raw bits extracted from hex string
    /// * `type_` - Data type ("UINT", "INT", "FLOAT", "STRING", "BLOCK")
    /// * `bit_length` - Number of bits in the value
    /// * `endianness` - Byte order ("BIG_ENDIAN" or "LITTLE_ENDIAN")
    fn parse_value(&self, bits: u128, type_: &str, bit_length: usize, endianness: &str) -> Result<ParsedValue> {
        let n_bytes = (bit_length + 7) / 8;

        match type_ {
            "BLOCK" => {
                // Binary data block - just record size
                Ok(ParsedValue::String(format!("<BLOCK {} bytes>", n_bytes)))
            }
            "UINT" => {
                // Unsigned integer with optional endianness conversion
                let value = if endianness == "LITTLE_ENDIAN" && bit_length > 8 {
                    let bytes = bits.to_le_bytes();
                    let mut result = 0u64;
                    for i in 0..n_bytes.min(8) {
                        result = (result << 8) | (bytes[i] as u64);
                    }
                    result
                } else {
                    bits as u64
                };
                Ok(ParsedValue::UInt(value))
            }
            "INT" => {
                // Signed integer with sign extension and endianness conversion
                let value = if endianness == "LITTLE_ENDIAN" && bit_length > 8 {
                    let bytes = bits.to_le_bytes();
                    let mut result = 0u64;
                    for i in 0..n_bytes.min(8) {
                        result = (result << 8) | (bytes[i] as u64);
                    }
                    // Sign extend if necessary
                    if bit_length < 64 && (result >> (bit_length - 1)) & 1 == 1 {
                        (result | (!0u64 << bit_length)) as i64
                    } else {
                        result as i64
                    }
                } else {
                    let unsigned = bits as u64;
                    // Sign extend if necessary
                    if bit_length < 64 && (unsigned >> (bit_length - 1)) & 1 == 1 {
                        (unsigned | (!0u64 << bit_length)) as i64
                    } else {
                        unsigned as i64
                    }
                };
                Ok(ParsedValue::Int(value))
            }
            "FLOAT" => {
                // IEEE 754 floating-point (32 or 64 bit)
                if bit_length == 32 {
                    let value = if endianness == "LITTLE_ENDIAN" {
                        // Convert little-endian bytes to big-endian for parsing
                        let int_val = bits as u32;
                        let be_bytes = int_val.to_be_bytes();
                        let reversed = [be_bytes[3], be_bytes[2], be_bytes[1], be_bytes[0]];
                        f32::from_be_bytes(reversed) as f64
                    } else {
                        let int_val = bits as u32;
                        let bytes = int_val.to_be_bytes();
                        f32::from_be_bytes(bytes) as f64
                    };
                    Ok(ParsedValue::Float(value))
                } else if bit_length == 64 {
                    let value = if endianness == "LITTLE_ENDIAN" {
                        // Convert little-endian bytes to big-endian for parsing
                        let int_val = bits as u64;
                        let be_bytes = int_val.to_be_bytes();
                        let reversed = [
                            be_bytes[7], be_bytes[6], be_bytes[5], be_bytes[4],
                            be_bytes[3], be_bytes[2], be_bytes[1], be_bytes[0]
                        ];
                        f64::from_be_bytes(reversed)
                    } else {
                        let int_val = bits as u64;
                        let bytes = int_val.to_be_bytes();
                        f64::from_be_bytes(bytes)
                    };
                    Ok(ParsedValue::Float(value))
                } else {
                    println!("Warning: Unsupported FLOAT bit length: {}", bit_length);
                    Err(rusqlite::Error::InvalidQuery)
                }
            }
            "STRING" => {
                // ASCII/UTF-8 string
                let bytes = bits.to_be_bytes();
                let start_idx = 16usize.saturating_sub(n_bytes.min(16));
                let s = String::from_utf8_lossy(&bytes[start_idx..])
                    .trim_end_matches('\0')
                    .to_string();
                Ok(ParsedValue::String(s))
            }
            _ => {
                // Unknown type - default to UINT
                println!("Warning: Unhandled type {}, treating as UINT", type_);
                Ok(ParsedValue::UInt(bits as u64))
            }
        }
    }

    /// Extract bits from a hex string at a specific bit offset.
    ///
    /// Handles bit-level extraction even when the bit range doesn't align
    /// with hex character boundaries (4 bits per char).
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Hex string (without "0x" prefix)
    /// * `bit_offset` - Starting bit position
    /// * `bit_length` - Number of bits to extract (max 128)
    ///
    /// # Returns
    ///
    /// The extracted bits as a u128 value
    fn extract_bits_from_hex(&self, hex_str: &str, bit_offset: usize, bit_length: usize) -> Result<u128> {
        if bit_length == 0 {
            return Ok(0);
        }
        
        // Limit to 128 bits
        if bit_length > 128 {
            return self.extract_bits_from_hex(hex_str, bit_offset, 128);
        }
        
        let start_bit = bit_offset;
        let end_bit = bit_offset + bit_length;
        
        // Convert bit positions to hex character positions
        let start_char = start_bit / 4;
        let end_char = (end_bit + 3) / 4;
        
        if start_char >= hex_str.len() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        
        let end_char = end_char.min(hex_str.len());
        let hex_slice = &hex_str[start_char..end_char];
        
        if hex_slice.is_empty() {
            return Ok(0);
        }
        
        // Parse hex string to integer
        let value = if hex_slice.len() <= 32 {
            u128::from_str_radix(hex_slice, 16).map_err(|_| rusqlite::Error::InvalidQuery)?
        } else {
            // Truncate if too long
            let truncated = &hex_slice[..32];
            u128::from_str_radix(truncated, 16).map_err(|_| rusqlite::Error::InvalidQuery)?
        };
        
        // Adjust for bit offset within the first hex character
        let bits_into_first_char = start_bit % 4;
        let bits_extracted = hex_slice.len().min(32) * 4;
        
        let bits_after_target = if bits_extracted > bits_into_first_char + bit_length {
            bits_extracted - bits_into_first_char - bit_length
        } else {
            0
        };
        
        // Shift to align the desired bits
        let shifted = if bits_after_target > 0 && bits_after_target < 128 {
            value >> bits_after_target
        } else {
            value
        };
        
        // Mask to extract only the desired bits
        let mask = if bit_length >= 128 {
            u128::MAX
        } else if bit_length == 0 {
            0
        } else {
            (1u128 << bit_length) - 1
        };
        
        Ok(shifted & mask)
    }

    /// Extract a string from hex data at a specific bit offset.
    ///
    /// Converts hex characters to bytes and handles bit-level alignment.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Hex string (without "0x" prefix)
    /// * `bit_offset` - Starting bit position
    /// * `bit_length` - Number of bits in the string
    fn extract_string_from_hex(&self, hex_str: &str, bit_offset: usize, bit_length: usize) -> Result<String> {
        let start_bit = bit_offset;
        let end_bit = bit_offset + bit_length;
        
        // Convert bit positions to hex character positions
        let start_char = start_bit / 4;
        let end_char = (end_bit + 3) / 4;
        
        if start_char >= hex_str.len() {
            return Ok(String::new());
        }
        
        let end_char = end_char.min(hex_str.len());
        let hex_slice = &hex_str[start_char..end_char];
        
        if hex_slice.is_empty() {
            return Ok(String::new());
        }
        
        // Convert hex to bytes
        let mut bytes = Vec::new();
        for i in (0..hex_slice.len()).step_by(2) {
            let end = (i + 2).min(hex_slice.len());
            if let Ok(byte) = u8::from_str_radix(&hex_slice[i..end], 16) {
                bytes.push(byte);
            }
        }
        
        // Handle bit offset within the first character
        let bits_into_first_char = start_bit % 4;
        if bits_into_first_char != 0 && !bytes.is_empty() {
            let shift = bits_into_first_char;
            // Shift bytes to align the string data
            for i in 0..bytes.len() - 1 {
                bytes[i] = (bytes[i] << shift) | (bytes[i + 1] >> (8 - shift));
            }
            if let Some(last) = bytes.last_mut() {
                *last = *last << shift;
            }
        }
        
        // Truncate to exact byte length
        let num_bytes = (bit_length + 7) / 8;
        bytes.truncate(num_bytes);
        
        // Convert to UTF-8 string, removing null terminators
        let s = String::from_utf8_lossy(&bytes)
            .trim_end_matches('\0')
            .to_string();
        
        Ok(s)
    }

    /// Match a raw value to a command parameter state name.
    ///
    /// # Arguments
    ///
    /// * `states` - List of possible states
    /// * `bits` - Raw value to match
    ///
    /// # Returns
    ///
    /// The state name if a match is found, None otherwise
    fn match_state_cmd(&self, states: &[CommandParameterState], bits: u128) -> Option<String> {
        for state in states {
            if let Some(state_value) = &state.state_value {
                if let Ok(val) = u128::from_str_radix(state_value.trim_start_matches("0x"), 16) {
                    if val == bits {
                        return state.state_name.clone();
                    }
                }
            }
        }
        None
    }

    /// Match a raw value to a telemetry state name.
    ///
    /// # Arguments
    ///
    /// * `states` - List of possible states
    /// * `bits` - Raw value to match
    ///
    /// # Returns
    ///
    /// The state name if a match is found, None otherwise
    fn match_state_tlm(&self, states: &[TelemetryState], bits: u128) -> Option<String> {
        for state in states {
            if let Ok(val) = u128::from_str_radix(state.state_value.trim_start_matches("0x"), 16) {
                if val == bits {
                    return Some(state.state_name.clone());
                }
            }
        }
        None
    }

    // ========================================================================
    // Database helper functions
    // ========================================================================

    /// Query all parameters for a command from the database.
    fn get_command_parameters(&self, conn: &Connection, command_id: i32) -> Result<Vec<CommandParameter>> {
        let mut stmt = conn.prepare(
            "SELECT id, command_id, name, bit_length, type, min, max, default_value, \
             description, is_array, array_length, format_string, endianness \
             FROM command_parameters WHERE command_id = ? ORDER BY id"
        )?;

        let params = stmt.query_map(params![command_id], |row| {
            Ok(CommandParameter {
                id: row.get(0)?,
                command_id: row.get(1)?,
                name: row.get(2)?,
                bit_length: row.get(3)?,
                type_: row.get(4)?,
                min: row.get(5)?,
                max: row.get(6)?,
                default_value: row.get(7)?,
                description: row.get(8)?,
                is_array: row.get(9)?,
                array_length: row.get(10)?,
                format_string: row.get(11)?,
                endianness: row.get(12)?,
            })
        })?;

        params.collect()
    }

    /// Query all items for a telemetry packet from the database.
    fn get_telemetry_items(&self, conn: &Connection, packet_id: i32) -> Result<Vec<TelemetryItem>> {
        let mut stmt = conn.prepare(
            "SELECT id, packet_id, name, bit_length, type, default_value, description, \
             is_id_field, format_string, units_name, units_symbol, endianness, item_order \
             FROM telemetry_items WHERE packet_id = ? ORDER BY item_order"
        )?;

        let items = stmt.query_map(params![packet_id], |row| {
            Ok(TelemetryItem {
                id: row.get(0)?,
                packet_id: row.get(1)?,
                name: row.get(2)?,
                bit_length: row.get(3)?,
                type_: row.get(4)?,
                default_value: row.get(5)?,
                description: row.get(6)?,
                is_id_field: row.get(7)?,
                format_string: row.get(8)?,
                units_name: row.get(9)?,
                units_symbol: row.get(10)?,
                endianness: row.get(11)?,
                item_order: row.get(12)?,
            })
        })?;

        items.collect()
    }

    /// Query state definitions for a command parameter.
    fn get_command_parameter_states(&self, conn: &Connection, parameter_id: i32) -> Result<Vec<CommandParameterState>> {
        let mut stmt = conn.prepare(
            "SELECT id, parameter_id, state_name, state_value \
             FROM command_parameter_states WHERE parameter_id = ?"
        )?;

        let states = stmt.query_map(params![parameter_id], |row| {
            Ok(CommandParameterState {
                id: row.get(0)?,
                parameter_id: row.get(1)?,
                state_name: row.get(2)?,
                state_value: row.get(3)?,
            })
        })?;

        states.collect()
    }

    /// Query state definitions for a telemetry item.
    fn get_telemetry_states(&self, conn: &Connection, item_id: i32) -> Result<Vec<TelemetryState>> {
        let mut stmt = conn.prepare(
            "SELECT id, item_id, state_name, state_value \
             FROM telemetry_states WHERE item_id = ?"
        )?;

        let states = stmt.query_map(params![item_id], |row| {
            Ok(TelemetryState {
                id: row.get(0)?,
                item_id: row.get(1)?,
                state_name: row.get(2)?,
                state_value: row.get(3)?,
            })
        })?;

        states.collect()
    }
}