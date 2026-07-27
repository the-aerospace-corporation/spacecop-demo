#!/usr/bin/env python3
"""
COSMOS to Zeek Analyzer Generator
Parses COSMOS/OpenC3 command and telemetry definitions and generates a Zeek analyzer
Configured for UDP ports: 5012 (commands), 5013 (telemetry)
"""

import re
import json
import os
import glob
from collections import defaultdict
from pathlib import Path

class CosmosParser:
    def __init__(self):
        self.commands = []
        self.telemetry = []
        self.targets = set()
        
        # Lookup tables
        self.stream_id_to_commands = defaultdict(list)
        self.stream_id_to_telemetry = defaultdict(list)
        self.apid_map = {}
        
    def parse_directory(self, directory, pattern="*.txt"):
        """Parse all COSMOS definition files in a directory"""
        files = glob.glob(os.path.join(directory, "**", pattern), recursive=True)
        
        print(f"Found {len(files)} files matching pattern '{pattern}'")
        
        for filepath in files:
            print(f"Parsing: {filepath}")
            self.parse_file(filepath)
        
        print(f"\nParsing complete:")
        print(f"  - Commands: {len(self.commands)}")
        print(f"  - Telemetry: {len(self.telemetry)}")
        print(f"  - Targets: {len(self.targets)}")
        
    def parse_file(self, filename):
        """Parse a single COSMOS definition file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"  ERROR reading {filename}: {e}")
            return
        
        lines = content.split('\n')
        current_item = None
        item_type = None
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                i += 1
                continue
            
            # Parse COMMAND
            if line.startswith('COMMAND '):
                if current_item and item_type == 'command':
                    self.commands.append(current_item)
                
                current_item = self._parse_command_header(line)
                item_type = 'command'
                if current_item:
                    self.targets.add(current_item['target'])
            
            # Parse TELEMETRY
            elif line.startswith('TELEMETRY '):
                if current_item and item_type == 'telemetry':
                    self.telemetry.append(current_item)
                
                current_item = self._parse_telemetry_header(line)
                item_type = 'telemetry'
                if current_item:
                    self.targets.add(current_item['target'])
            
            # Parse parameters/items
            elif current_item:
                if line.startswith('APPEND_ID_PARAMETER') or line.startswith('APPEND_PARAMETER'):
                    param = self._parse_parameter(line)
                    if param:
                        current_item['parameters'].append(param)
                        
                        # Track CCSDS_STREAMID for indexing
                        if param['name'] == 'CCSDS_STREAMID':
                            stream_id = self._extract_value(param.get('init_val', param.get('min_val')))
                            if stream_id is not None:
                                current_item['stream_id'] = stream_id
                                if item_type == 'command':
                                    self.stream_id_to_commands[stream_id].append(current_item)
                
                elif line.startswith('APPEND_ID_ITEM') or line.startswith('APPEND_ITEM') or line.startswith('ITEM'):
                    item = self._parse_item(line)
                    if item:
                        current_item['parameters'].append(item)
                        
                        # Track CCSDS_STREAMID
                        if item['name'] == 'CCSDS_STREAMID':
                            stream_id = self._extract_value(item.get('default'))
                            if stream_id is not None:
                                current_item['stream_id'] = stream_id
                                if item_type == 'telemetry':
                                    self.stream_id_to_telemetry[stream_id].append(current_item)
                
                # Handle ID_PARAMETER or ID_ITEM for identification
                elif line.startswith('ID_PARAMETER') or line.startswith('ID_ITEM'):
                    id_item = self._parse_id_item(line)
                    if id_item:
                        current_item['id_items'] = current_item.get('id_items', [])
                        current_item['id_items'].append(id_item)
            
            i += 1
        
        # Add last item
        if current_item:
            if item_type == 'command':
                self.commands.append(current_item)
            elif item_type == 'telemetry':
                self.telemetry.append(current_item)
    
    def _parse_command_header(self, line):
        """Parse COMMAND header line"""
        parts = self._split_preserve_quotes(line)
        
        if len(parts) < 3:
            return None
        
        return {
            'type': 'command',
            'target': parts[1] if len(parts) > 1 else '',
            'name': parts[2] if len(parts) > 2 else '',
            'endian': parts[3] if len(parts) > 3 else 'BIG_ENDIAN',
            'description': self._unquote(parts[4]) if len(parts) > 4 else '',
            'parameters': [],
            'stream_id': None,
            'function_code': None
        }
    
    def _parse_telemetry_header(self, line):
        """Parse TELEMETRY header line"""
        parts = self._split_preserve_quotes(line)
        
        if len(parts) < 3:
            return None
        
        return {
            'type': 'telemetry',
            'target': parts[1] if len(parts) > 1 else '',
            'name': parts[2] if len(parts) > 2 else '',
            'endian': parts[3] if len(parts) > 3 else 'BIG_ENDIAN',
            'description': self._unquote(parts[4]) if len(parts) > 4 else '',
            'parameters': [],
            'stream_id': None
        }
    
    def _parse_parameter(self, line):
        """Parse APPEND_PARAMETER or APPEND_ID_PARAMETER"""
        line = re.sub(r'^APPEND_ID_PARAMETER\s+|^APPEND_PARAMETER\s+', '', line)
        parts = self._split_preserve_quotes(line)
        
        if len(parts) < 3:
            return None
        
        param = {
            'name': parts[0],
            'bits': self._parse_int(parts[1]) if len(parts) > 1 else 0,
            'type': parts[2] if len(parts) > 2 else 'UINT',
            'min_val': parts[3] if len(parts) > 3 else None,
            'max_val': parts[4] if len(parts) > 4 else None,
            'init_val': parts[5] if len(parts) > 5 else None,
            'description': self._unquote(parts[6]) if len(parts) > 6 else '',
            'endian': parts[7] if len(parts) > 7 else None,
        }
        
        return param
    
    def _parse_item(self, line):
        """Parse APPEND_ITEM, APPEND_ID_ITEM, or ITEM"""
        line = re.sub(r'^APPEND_ID_ITEM\s+|^APPEND_ITEM\s+|^ITEM\s+', '', line)
        parts = self._split_preserve_quotes(line)
        
        if len(parts) < 3:
            return None
        
        item = {
            'name': parts[0],
            'bit_offset': self._parse_int(parts[1]) if len(parts) > 1 else 0,
            'bit_size': self._parse_int(parts[2]) if len(parts) > 2 else 0,
            'type': parts[3] if len(parts) > 3 else 'UINT',
            'description': self._unquote(parts[4]) if len(parts) > 4 else '',
            'endian': parts[5] if len(parts) > 5 else None,
        }
        
        return item
    
    def _parse_id_item(self, line):
        """Parse ID_PARAMETER or ID_ITEM for packet identification"""
        parts = self._split_preserve_quotes(line)
        
        if len(parts) < 6:
            return None
        
        return {
            'name': parts[1],
            'bit_offset': self._parse_int(parts[2]),
            'bit_size': self._parse_int(parts[3]),
            'type': parts[4],
            'id_value': parts[5],
        }
    
    def _split_preserve_quotes(self, line):
        """Split line by whitespace but preserve quoted strings"""
        return re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', line)
    
    def _unquote(self, s):
        """Remove surrounding quotes"""
        if s and s[0] == '"' and s[-1] == '"':
            return s[1:-1]
        return s
    
    def _parse_int(self, s):
        """Parse integer (handles hex)"""
        if not s:
            return 0
        try:
            if isinstance(s, str) and s.startswith('0x'):
                return int(s, 16)
            return int(s)
        except:
            return 0
    
    def _extract_value(self, val):
        """Extract numeric value from string (handles hex, constants, etc.)"""
        if val is None:
            return None
        
        if isinstance(val, int):
            return val
        
        val = str(val).strip()
        
        # Hex value
        if val.startswith('0x') or val.startswith('0X'):
            try:
                return int(val, 16)
            except:
                return None
        
        # Decimal value
        try:
            return int(val)
        except:
            return None
    
    def _build_lookup_tables(self):
        """Build optimized lookup tables for Zeek"""
        # Command lookup: [stream_id, function_code] -> command info
        cmd_lookup = {}
        for cmd in self.commands:
            stream_id = cmd.get('stream_id')
            func_code = None
            
            # Find function code
            for param in cmd['parameters']:
                if param['name'] in ['CCSDS_FC', 'FUNCTION_CODE', 'CMD_CODE']:
                    func_code = self._extract_value(param.get('init_val'))
                    break
            
            if stream_id is not None and func_code is not None:
                key = (stream_id, func_code)
                cmd_lookup[key] = {
                    'target': cmd['target'],
                    'name': cmd['name'],
                    'description': cmd['description'],
                    'parameters': cmd['parameters']
                }
        
        # Telemetry lookup: stream_id -> telemetry info
        tlm_lookup = {}
        for tlm in self.telemetry:
            stream_id = tlm.get('stream_id')
            if stream_id is not None:
                tlm_lookup[stream_id] = {
                    'target': tlm['target'],
                    'name': tlm['name'],
                    'description': tlm['description'],
                    'parameters': tlm['parameters']
                }
        
        return cmd_lookup, tlm_lookup
    
    def generate_zeek_analyzer(self, output_file='ccsds_analyzer.zeek'):
        """Generate comprehensive Zeek analyzer for UDP ports 5012/5013"""
        cmd_lookup, tlm_lookup = self._build_lookup_tables()
        
        zeek_code = self._generate_zeek_header()
        zeek_code += self._generate_command_table(cmd_lookup)
        zeek_code += self._generate_telemetry_table(tlm_lookup)
        zeek_code += self._generate_zeek_parser()
        zeek_code += self._generate_zeek_events()
        
        with open(output_file, 'w') as f:
            f.write(zeek_code)
        
        print(f"\n✓ Generated Zeek analyzer: {output_file}")
        print(f"  - Commands: {len(cmd_lookup)}")
        print(f"  - Telemetry: {len(tlm_lookup)}")
        print(f"  - UDP Command Port: 5012")
        print(f"  - UDP Telemetry Port: 5013")
    
    def _generate_zeek_header(self):
        return '''# Auto-generated CCSDS/COSMOS Packet Analyzer for Zeek
# Generated from COSMOS command and telemetry definitions
# UDP Port 5012: Commands
# UDP Port 5013: Telemetry

@load base/protocols/conn

module CCSDS;

export {
    redef enum Log::ID += { COMMAND_LOG, TELEMETRY_LOG };
    
    # Command packet record
    type CommandInfo: record {
        ts: time &log;
        uid: string &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        
        # CCSDS Header
        stream_id: count &log &optional;
        stream_id_hex: string &log &optional;
        apid: count &log &optional;
        sequence_flags: count &log &optional;
        packet_sequence: count &log &optional;
        data_length: count &log &optional;
        
        # Command-specific
        function_code: count &log &optional;
        checksum: count &log &optional;
        
        # Decoded info
        target: string &log &optional;
        command_name: string &log &optional;
        command_desc: string &log &optional;
        
        # Raw data
        raw_hex: string &log &optional;
        packet_length: count &log;
        
        # Validation
        valid: bool &log &default=F;
        error: string &log &optional;
    };
    
    # Telemetry packet record
    type TelemetryInfo: record {
        ts: time &log;
        uid: string &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        
        # CCSDS Header
        stream_id: count &log &optional;
        stream_id_hex: string &log &optional;
        apid: count &log &optional;
        sequence_flags: count &log &optional;
        packet_sequence: count &log &optional;
        data_length: count &log &optional;
        
        # Decoded info
        target: string &log &optional;
        packet_name: string &log &optional;
        packet_desc: string &log &optional;
        
        # Raw data
        raw_hex: string &log &optional;
        packet_length: count &log;
        
        # Validation
        valid: bool &log &default=F;
        error: string &log &optional;
    };
    
    # Port definitions - UDP only
    const COMMAND_PORT = 5012/udp &redef;
    const TELEMETRY_PORT = 5013/udp &redef;
}

# CRITICAL: Zeek does NOT raise the udp_contents event unless the port is
# registered for content delivery (or deliver-all is enabled). Without these
# redefs the udp_contents handler below never fires and NO log is ever written
# -- Zeek still starts cleanly, which makes it look like it is working.
redef udp_content_delivery_ports_orig += { [COMMAND_PORT] = T, [TELEMETRY_PORT] = T };
redef udp_content_delivery_ports_resp += { [COMMAND_PORT] = T, [TELEMETRY_PORT] = T };

event zeek_init()
    {
    Log::create_stream(COMMAND_LOG, [$columns=CommandInfo, $path="ccsds_commands"]);
    Log::create_stream(TELEMETRY_LOG, [$columns=TelemetryInfo, $path="ccsds_telemetry"]);
    }

'''
    
    def _generate_command_table(self, cmd_lookup):
        """Generate flat command lookup table using string keys"""
        code = '''# Command lookup table: "stream_id_function_code" -> [target, name, description]
    const command_table: table[string] of vector of string = {
    '''
        
        # Generate flat string-keyed table with explicit vector construction
        for (stream_id, func_code), info in sorted(cmd_lookup.items()):
            target = info['target'].replace('"', '\\"').replace('\n', ' ')
            name = info['name'].replace('"', '\\"').replace('\n', ' ')
            desc = info['description'].replace('"', '\\"').replace('\n', ' ')
            key = f"{stream_id}_{func_code}"
            # Use vector() constructor explicitly
            code += f'    ["{key}"] = vector("{target}", "{name}", "{desc}"),\n'
        
        code += '''} &redef;

    '''
        return code
    
    def _generate_telemetry_table(self, tlm_lookup):
        code = '''# Telemetry lookup table: stream_id -> [target, name, description]
    const telemetry_table: table[count] of vector of string = {
    '''
        
        for stream_id in sorted(tlm_lookup.keys()):
            info = tlm_lookup[stream_id]
            target = info['target'].replace('"', '\\"').replace('\n', ' ')
            name = info['name'].replace('"', '\\"').replace('\n', ' ')
            desc = info['description'].replace('"', '\\"').replace('\n', ' ')
            # Use vector() constructor explicitly
            code += f'    [{stream_id}] = vector("{target}", "{name}", "{desc}"),\n'
        
        code += '''} &redef;

    '''
        return code
    
    def _generate_zeek_parser(self):
        return '''# Utility functions for parsing

function extract_uint16_be(data: string, offset: count): count
    {
    if (|data| < offset + 2)
        return 0;
    
    local byte_vec = raw_bytes_to_v4_addr(data);
    local b1: count = 0;
    local b2: count = 0;
    
    # Safe byte extraction
    local len = |data|;
    if (offset < len)
        b1 = bytestring_to_count(data[offset]);
    if (offset + 1 < len)
        b2 = bytestring_to_count(data[offset + 1]);
    
    return (b1 * 256) + b2;
    }

function extract_uint8(data: string, offset: count): count
    {
    if (|data| <= offset)
        return 0;
    
    return bytestring_to_count(data[offset]);
    }

function to_hex_string(data: string): string
    {
    local hex = "";
    local len = |data|;
    local i = 0;
    
    while (i < len)
        {
        if (hex != "")
            hex = fmt("%s ", hex);
        hex = fmt("%s%02X", hex, bytestring_to_count(data[i]));
        i = i + 1;
        }
    
    return hex;
    }

function parse_command_packet(payload: string): CommandInfo
    {
    local info: CommandInfo;
    info$packet_length = |payload|;
    info$raw_hex = to_hex_string(payload);
    
    if (|payload| < 6)
        {
        info$error = fmt("Packet too short: %d bytes", |payload|);
        return info;
        }
    
    # Parse CCSDS Primary Header (6 bytes)
    local stream_id = extract_uint16_be(payload, 0);
    local sequence = extract_uint16_be(payload, 2);
    local data_length = extract_uint16_be(payload, 4);
    
    info$stream_id = stream_id;
    info$stream_id_hex = fmt("0x%04X", stream_id);
    info$sequence_flags = (sequence / 16384) % 4;  # Right shift 14 bits
    info$packet_sequence = sequence % 16384;        # Lower 14 bits
    info$data_length = data_length;
    info$apid = stream_id % 2048;                   # Lower 11 bits
    
    # Parse Secondary Header (Command-specific)
    if (|payload| >= 7)
        {
        local fc = extract_uint8(payload, 6);
        info$function_code = fc;
        
        if (|payload| >= 8)
            {
            info$checksum = extract_uint8(payload, 7);
            }
        
        # Look up command using string key
        local lookup_key = fmt("%d_%d", stream_id, fc);
        if (lookup_key in command_table)
            {
            local cmd = command_table[lookup_key];
            info$target = cmd[0];
            info$command_name = cmd[1];
            info$command_desc = cmd[2];
            info$valid = T;
            }
        else
            {
            info$error = fmt("Unknown command: StreamID=0x%04X, FC=%d", stream_id, fc);
            }
        }
    else
        {
        info$error = "No secondary header";
        }
    
    return info;
    }

function parse_telemetry_packet(payload: string): TelemetryInfo
    {
    local info: TelemetryInfo;
    info$packet_length = |payload|;
    info$raw_hex = to_hex_string(payload);
    
    if (|payload| < 6)
        {
        info$error = fmt("Packet too short: %d bytes", |payload|);
        return info;
        }
    
    # Parse CCSDS Primary Header (6 bytes)
    local stream_id = extract_uint16_be(payload, 0);
    local sequence = extract_uint16_be(payload, 2);
    local data_length = extract_uint16_be(payload, 4);
    
    info$stream_id = stream_id;
    info$stream_id_hex = fmt("0x%04X", stream_id);
    info$sequence_flags = (sequence / 16384) % 4;
    info$packet_sequence = sequence % 16384;
    info$data_length = data_length;
    info$apid = stream_id % 2048;
    
    # Look up telemetry
    if (stream_id in telemetry_table)
        {
        local tlm = telemetry_table[stream_id];
        info$target = tlm[0];
        info$packet_name = tlm[1];
        info$packet_desc = tlm[2];
        info$valid = T;
        }
    else
        {
        info$error = fmt("Unknown telemetry: StreamID=0x%04X", stream_id);
        info$target = "UNKNOWN";
        info$packet_name = "UNKNOWN";
        }
    
    return info;
    }

'''
    
    def _generate_zeek_events(self):
        return '''# UDP event handler - Port-based packet type detection

event udp_contents(c: connection, is_orig: bool, payload: string)
    {
    local src_port = c$id$orig_p;
    local dst_port = c$id$resp_p;
    
    # Skip if not our ports
    if (src_port != COMMAND_PORT && dst_port != COMMAND_PORT &&
        src_port != TELEMETRY_PORT && dst_port != TELEMETRY_PORT)
        return;
    
    # Skip empty payloads
    if (|payload| < 6)
        return;
    
    # Determine packet type based on port
    if (src_port == COMMAND_PORT || dst_port == COMMAND_PORT)
        {
        # This is a command packet (port 5012)
        local cmd_info = parse_command_packet(payload);
        cmd_info$ts = network_time();
        cmd_info$uid = c$uid;
        cmd_info$src_ip = c$id$orig_h;
        cmd_info$src_port = src_port;
        cmd_info$dst_ip = c$id$resp_h;
        cmd_info$dst_port = dst_port;
        
        Log::write(COMMAND_LOG, cmd_info);
        }
    else if (src_port == TELEMETRY_PORT || dst_port == TELEMETRY_PORT)
        {
        # This is a telemetry packet (port 5013)
        local tlm_info = parse_telemetry_packet(payload);
        tlm_info$ts = network_time();
        tlm_info$uid = c$uid;
        tlm_info$src_ip = c$id$orig_h;
        tlm_info$src_port = src_port;
        tlm_info$dst_ip = c$id$resp_h;
        tlm_info$dst_port = dst_port;
        
        Log::write(TELEMETRY_LOG, tlm_info);
        }
    }
'''
    
    def export_to_json(self, output_file='cosmos_definitions.json'):
        """Export all parsed definitions to JSON"""
        data = {
            'targets': list(self.targets),
            'commands': self.commands,
            'telemetry': self.telemetry,
            'statistics': {
                'total_commands': len(self.commands),
                'total_telemetry': len(self.telemetry),
                'total_targets': len(self.targets)
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✓ Exported definitions to: {output_file}")
    
    def generate_summary_report(self, output_file='cosmos_summary.txt'):
        """Generate a human-readable summary report"""
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("COSMOS DEFINITIONS SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total Targets: {len(self.targets)}\n")
            f.write(f"Total Commands: {len(self.commands)}\n")
            f.write(f"Total Telemetry: {len(self.telemetry)}\n\n")
            
            # Commands by target
            f.write("-" * 80 + "\n")
            f.write("COMMANDS BY TARGET\n")
            f.write("-" * 80 + "\n")
            
            cmds_by_target = defaultdict(list)
            for cmd in self.commands:
                cmds_by_target[cmd['target']].append(cmd)
            
            for target in sorted(cmds_by_target.keys()):
                f.write(f"\n{target}:\n")
                for cmd in cmds_by_target[target]:
                    stream_id = cmd.get('stream_id', 'N/A')
                    if isinstance(stream_id, int):
                        stream_id = f"0x{stream_id:04X}"
                    f.write(f"  - {cmd['name']} (StreamID: {stream_id})\n")
                    if cmd['description']:
                        f.write(f"    {cmd['description']}\n")
            
            # Telemetry by target
            f.write("\n" + "-" * 80 + "\n")
            f.write("TELEMETRY BY TARGET\n")
            f.write("-" * 80 + "\n")
            
            tlm_by_target = defaultdict(list)
            for tlm in self.telemetry:
                tlm_by_target[tlm['target']].append(tlm)
            
            for target in sorted(tlm_by_target.keys()):
                f.write(f"\n{target}:\n")
                for tlm in tlm_by_target[target]:
                    stream_id = tlm.get('stream_id', 'N/A')
                    if isinstance(stream_id, int):
                        stream_id = f"0x{stream_id:04X}"
                    f.write(f"  - {tlm['name']} (StreamID: {stream_id})\n")
                    if tlm['description']:
                        f.write(f"    {tlm['description']}\n")
        
        print(f"✓ Generated summary report: {output_file}")

# Main execution
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse COSMOS definitions and generate Zeek analyzer for UDP ports 5012/5013',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Parse a directory
  python3 cosmos_to_zeek.py /path/to/cosmos/config
  
  # Parse with custom pattern
  python3 cosmos_to_zeek.py /path/to/cosmos/config --pattern "*.txt"
  
  # Parse single file
  python3 cosmos_to_zeek.py camera_commands.txt
  
  # Custom output names
  python3 cosmos_to_zeek.py /path/to/cosmos --output my_analyzer.zeek
        '''
    )
    parser.add_argument(
        'path',
        help='Directory containing COSMOS definition files, or single file'
    )
    parser.add_argument(
        '--pattern',
        default='*.txt',
        help='File pattern to match (default: *.txt)'
    )
    parser.add_argument(
        '--output',
        default='ccsds_analyzer.zeek',
        help='Output Zeek script filename (default: ccsds_analyzer.zeek)'
    )
    parser.add_argument(
        '--json',
        default='cosmos_definitions.json',
        help='Output JSON filename (default: cosmos_definitions.json)'
    )
    parser.add_argument(
        '--summary',
        default='cosmos_summary.txt',
        help='Output summary report filename (default: cosmos_summary.txt)'
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("COSMOS TO ZEEK ANALYZER GENERATOR")
    print("UDP Port 5012: Commands | UDP Port 5013: Telemetry")
    print("=" * 80)
    print()
    
    cosmos_parser = CosmosParser()
    
    # Parse files
    if os.path.isdir(args.path):
        print(f"📁 Parsing directory: {args.path}")
        cosmos_parser.parse_directory(args.path, args.pattern)
    elif os.path.isfile(args.path):
        print(f"📄 Parsing file: {args.path}")
        cosmos_parser.parse_file(args.path)
    else:
        print(f"❌ ERROR: Path not found: {args.path}")
        sys.exit(1)
    
    # Generate outputs
    print("\n" + "=" * 80)
    print("GENERATING OUTPUTS")
    print("=" * 80)
    cosmos_parser.generate_zeek_analyzer(args.output)
    cosmos_parser.export_to_json(args.json)
    cosmos_parser.generate_summary_report(args.summary)
    
    print("\n" + "=" * 80)
    print("✅ COMPLETE!")
    print("=" * 80)
    print(f"\nFiles generated:")
    print(f"  1. {args.output} - Zeek analyzer script")
    print(f"  2. {args.json} - JSON definitions")
    print(f"  3. {args.summary} - Human-readable summary")
    print(f"\nNext steps:")
    print(f"  1. Review the summary: cat {args.summary}")
    print(f"  2. Copy to Zeek: sudo cp {args.output} /opt/zeek/share/zeek/site/")
    print(f"  3. Edit local.zeek: sudo nano /opt/zeek/share/zeek/site/local.zeek")
    print(f"     Add this line: @load ./{args.output}")
    print(f"  4. Deploy: sudo /opt/zeek/bin/zeekctl deploy")
    print(f"  5. Start: sudo systemctl start zeek")