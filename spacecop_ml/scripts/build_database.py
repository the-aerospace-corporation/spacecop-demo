import os
import re
# import fnmatch
import shlex
from models import app, db, Command, CommandParameter, CommandParameterState, TelemetryPacket, TelemetryItem, TelemetryState

DEFAULT_ENDIAN = "BIG_ENDIAN"

def parse_command_file(filepath):
    with open(filepath, 'r') as f:
        raw = f.read()

    expanded = expand_erb_loops(raw)
    lines = expanded.splitlines()

    results = []
    current_command = None
    current_param = None

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if line.startswith("#"):
            continue
        elif line.startswith('COMMAND'):
            parts = line.split(' ', 4)
            current_command = {
                'system': parts[1],
                'name': parts[2],
                'endian': parts[3],
                'description': parts[4].strip('"'),
                'parameters': []
            }
            results.append(current_command)

        elif line.startswith('APPEND_PARAMETER') or line.startswith('APPEND_ID_PARAMETER'):
            match = re.match(
                r'APPEND_(ID_)?PARAMETER\s+(\w+)\s+(\d+)\s+(\w+)\s+(?:(\S+)\s+(\S+)\s+(\S+)|"([^"]*)")\s+"([^"]*)"(?:\s+(BIG_ENDIAN|LITTLE_ENDIAN))?', line)

            if match:
                # Basic groups
                is_id_param = bool(match.group(1))
                name = match.group(2)
                bits = int(match.group(3))
                dtype = match.group(4)
                description = match.group(9)
                endianness = match.group(10)

                # Handle STRING or Numeric-style init values
                if match.group(8) is not None:  # It's a quoted string
                    default = match.group(8)
                    min_val = None
                    max_val = None
                else:  # Numeric style (MIN MAX INIT)
                    min_val = match.group(5)
                    max_val = match.group(6)
                    default = match.group(7)

                current_param = {
                    'name': name,
                    'bit_length': bits,
                    'type': dtype,
                    'min': min_val,
                    'max': max_val,
                    'default': default,
                    'description': description,
                    'states': [],
                    'is_id_field': is_id_param,
                    "endianness": endianness
                }

                if current_command:
                    current_command['parameters'].append(current_param)


        elif line.startswith('STATE') and current_param:
            try:
                _, state_name, state_value = shlex.split(line)
                current_param['states'].append({
                    'state_name': state_name,
                    'state_value': state_value
                })
            except:
                print(line)
        elif line.startswith('APPEND_ARRAY_PARAMETER'):
            
            param_match = re.match(
                # r'APPEND_ARRAY_PARAMETER\s+(\w+)\s+(\d+)\s+(\w+)(?:\s+(\S+)\s+(\S+)\s+(\S+))?\s+',
                r'APPEND_ARRAY_PARAMETER\s+(\w+)\s+(\d+)\s+(\w+)\s+(\d+)\s+"([^"]*)"(?:\s+(BIG_ENDIAN|LITTLE_ENDIAN))?',
                line
            ) #APPEND_ARRAY_PARAMETER SPARE 8 UINT 24 "Spare - Unused"

            if param_match:
                name, bit_length, dtype, array_length, description, endianness = param_match.groups()
                current_param = {
                    'name': name,
                    'bit_length': int(bit_length),
                    'type': dtype,
                    'description': description,
                    'states': [],
                    'is_array': True,
                    'endianness':endianness
                }
                current_param['array_length'] = int(array_length) if array_length else 1
                current_param['min'] = None
                current_param['max'] = None
                current_param['default'] = None

                if current_command:
                    current_command['parameters'].append(current_param)

        elif line.startswith('FORMAT_STRING') and current_param:
            # Safely parse quoted format string
            match = re.match(r'FORMAT_STRING\s+"(.+)"', line)
            if match:
                current_param['format_string'] = match.group(1)
        else:
            print("I need to be parsed")
            print(line)

    return results


def insert_parsed_commands(commands):
    for cmd in commands:
        command = Command(system=cmd['system'], name=cmd['name'], endian=cmd['endian'], description=cmd['description'])
        db.session.add(command)

        for param in cmd['parameters']:
            parameter = CommandParameter(
                name=param['name'],
                bit_length=param['bit_length'],
                type=param['type'],
                min=param.get('min'),
                max=param.get('max'),
                default_value=param.get('default'),
                description=param['description'],
                is_array=param.get('is_array', False),
                array_length=param.get('array_length'),
                format_string=param.get('format_string'),  # NEW
                endianness=param.get('endianness') if param.get('endianness') else cmd.get('endian'), # NEW
                command=command
            )
            db.session.add(parameter)

            for state in param['states']:
                ps = CommandParameterState(
                    parameter=parameter,
                    state_name=state['state_name'],
                    state_value=state['state_value']
                )
                db.session.add(ps)

    db.session.commit()


def expand_erb_loops(text):
    def _expand_block(lines, parent_scope):
        output = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("#"):
                pass
            else:
                # Match an 'each' loop
                match_each = re.match(r"<%\s*\(?(\d+)\s*\.\.\s*(\d+)\)?\.each do \|(\w+)\|\s*%>", line)
                if match_each:
                    start, end, var = int(match_each[1]), int(match_each[2]), match_each[3]
                    i += 1
                    loop_lines = []
                    nested = 1  # count the nesting level of <% %>

                    while i < len(lines):
                        sub_line = lines[i].strip()
                        # Check for nested loops
                        if sub_line.startswith("#"):
                            pass
                        if re.match(r"<%.*each.*do.*%>", sub_line):
                            nested += 1
                        if re.match(r"<%\s*\((\d+)\)\.downto\((\d+)\)\s*do \|(\w+)\|\s*%>", sub_line):
                            nested += 1
                        elif sub_line == "<% end %>":
                            nested -= 1
                            if nested == 0:
                                break
                        loop_lines.append(lines[i])
                        i += 1
                    i += 1  # skip final <% end %>

                    # Execute loop
                    for val in range(start, end + 1):
                        scope = parent_scope.copy()
                        scope[var] = val
                        output.extend(_expand_block(loop_lines, scope))
                    continue

                # Match a 'downto' loop <% (3).downto(0) do |y| %>
                match_down = re.match(r"<%\s*\((\d+)\)\.downto\((\d+)\)\s*do \|(\w+)\|\s*%>", line)
                if match_down:
                    start, end, var = int(match_down[1]), int(match_down[2]), match_down[3]
                    i += 1
                    loop_lines = []
                    nested = 1

                    while i < len(lines):
                        sub_line = lines[i].strip()
                        if sub_line.startswith("#"):
                            pass
                        if re.match(r"<%.*do.*%>", sub_line):
                            nested += 1
                        if re.match(r"<%\s*\(?(\d+)\s*\.\.\s*(\d+)\)?\.each do \|(\w+)\|\s*%>", sub_line):
                            nested += 1
                        elif sub_line == "<% end %>":
                            nested -= 1
                            if nested == 0:
                                break
                        loop_lines.append(lines[i])
                        i += 1
                    i += 1  # skip final <% end %>

                    for val in range(start, end - 1, -1):
                        scope = parent_scope.copy()
                        scope[var] = val
                        output.extend(_expand_block(loop_lines, scope))
                    continue

                # Handle substitutions like <%= x %> and <% (x+1)*y %>
                def replace_expr(match):
                    expr = match.group(1).strip()

                    # Handle special constants
                    if expr == "CosmosCfsConfig::PROCESSOR_ENDIAN":
                        return DEFAULT_ENDIAN

                    # Safe evaluation: only allow simple arithmetic with variables from scope
                    try:
                        # Replace variables with their values
                        for var, val in parent_scope.items():
                            expr = expr.replace(var, str(val))

                        # Now evaluate simple arithmetic expressions safely
                        # Only allow digits, operators, parentheses, and whitespace
                        if re.match(r'^[\d\s\+\-\*\/\(\)\.]+$', expr):
                            return str(eval(expr, {"__builtins__": {}}, {}))
                        else:
                            # If not a simple arithmetic expression, return as-is
                            return expr
                    except Exception as e:
                        print(line)
                        print(f"[ERB ERROR] Failed to process {expr!r} with scope {parent_scope}: {e}")
                        return f"<error:{expr}>"

                expanded_line = re.sub(r"<%= (.*?) %>", replace_expr, lines[i])
                output.append(expanded_line)
            i += 1

        return output

    lines = text.splitlines()
    expanded = _expand_block(lines, {})
    return "\n".join(expanded)

def parse_telemetry_file(filepath):
    with open(filepath, 'r') as f:
        raw = f.read()

    expanded = expand_erb_loops(raw)
    lines = expanded.splitlines()

    results = []
    current_packet = None
    current_item = None

    item_order = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Start of a telemetry packet
        elif line.startswith("TELEMETRY"):
            parts = line.split(" ", 4)
            current_packet = {
                "system": parts[1],
                "name": parts[2],
                "endian": parts[3],
                "description": parts[4].strip('"'),
                "items": [],
            }
            results.append(current_packet)
            current_item = None

        # APPEND_ITEM or APPEND_ID_ITEM
        elif line.startswith("APPEND_ITEM") or line.startswith("APPEND_ID_ITEM"):
            is_id = line.startswith("APPEND_ID_ITEM")
            match = re.match(
                r'APPEND_(ID_)?ITEM\s+(\w+)\s+(\d+)\s+(\w+)(?:\s+(0x[0-9A-Fa-f]+|\d+))?\s+"(.*?)"(?:\s+(BIG_ENDIAN|LITTLE_ENDIAN))?',
                line
            )
            if match:
                _, name, bits, dtype, default_val, description, endianness = match.groups()
                current_item = {
                    "name": name,
                    "bit_length": int(bits),
                    "type": dtype,
                    "default_value": default_val,
                    "description": description,
                    "is_id_field": is_id,
                    "format_string": None,
                    "units_name": None,
                    "units_symbol": None,
                    "endianness": endianness,
                    "states": [],
                    "item_order": item_order
                }
                current_packet["items"].append(current_item)
                item_order += 1

        # FORMAT_STRING under APPEND_ITEM
        elif line.startswith("FORMAT_STRING") and current_item:
            fmt_match = re.match(r'FORMAT_STRING\s+"(.+)"', line)
            if fmt_match:
                current_item["format_string"] = fmt_match.group(1)

        # UNITS under APPEND_ITEM
        elif line.startswith("UNITS") and current_item:
            parts = line.split(maxsplit=2)
            if len(parts) == 3:
                current_item["units_name"] = parts[1]
                current_item["units_symbol"] = parts[2]

        # STATE under APPEND_ITEM
        elif line.startswith("STATE") and current_item:
            parts = re.split(r'\s+', line) # Dropping GREEN from "STATE ENABLED 0 GREEN"
            if len(parts) >= 3:
                state_name = parts[1]
                state_value = parts[2]
                current_item["states"].append({
                    "state_name": state_name,
                    "state_value": state_value
                })
        elif not line.startswith("<%") and not line.startswith("READ_COVERSION"):
            print("i need parsed")
            print(line)

    return results


def insert_parsed_telemetry(packets):
    for pkt in packets:
        packet = TelemetryPacket(
            system=pkt['system'],
            name=pkt['name'],
            endian=pkt['endian'],
            description=pkt['description']
        )
        db.session.add(packet)

        for item in pkt['items']:
            db_item = TelemetryItem(
                packet=packet,
                name=item['name'],
                bit_length=item['bit_length'],
                type=item['type'],
                default_value=item.get('default_value'),
                description=item.get('description'),
                is_id_field=item.get('is_id_field', False),
                format_string=item.get('format_string'),
                units_name=item.get('units_name'),
                units_symbol=item.get('units_symbol'),
                endianness=item.get('endianness') if item.get('endianness') else pkt.get('endian'),
                item_order=item.get("item_order")
            )
            db.session.add(db_item)

            for state in item.get('states', []):
                db.session.add(TelemetryState(
                    item=db_item,
                    state_name=state['state_name'],
                    state_value=state['state_value']
                ))

    db.session.commit()

def process_directory_tree(root_dir):
    """Process directory tree and parse command/telemetry files"""
    if not os.path.isdir(root_dir):
        raise ValueError(f"Invalid directory: {root_dir}")

    cmd_count = 0
    tlm_count = 0

    for dirpath, _, filenames in os.walk(root_dir):
        # Skip COSMOS screen definitions - they are also *.txt but are NOT
        # command/telemetry packet definitions (they'd fail to parse).
        if "screens" in dirpath.split(os.sep):
            continue

        for filename in filenames:
            lower_name = filename.lower()

            # Match both the OpenC3 target naming ("cmd.txt" / "tlm.txt", e.g.
            # targets/CAMERA/cmd_tlm/cmd.txt) and the NOS3 naming
            # ("<app>_cmd.txt" / "<app>_tlm.txt"). Using endswith() rather than a
            # substring test is what makes the plain "cmd.txt"/"tlm.txt" files
            # get picked up.
            if lower_name.endswith("tlm.txt"):
                filepath = os.path.join(dirpath, filename)
                print(f"  Parsing TELEMETRY: {filename}")
                try:
                    parsed = parse_telemetry_file(filepath)
                    insert_parsed_telemetry(parsed)
                    tlm_count += len(parsed)
                except Exception as e:
                    print(f"    ERROR: {e}")

            elif lower_name.endswith("cmd.txt"):
                filepath = os.path.join(dirpath, filename)
                print(f"  Parsing COMMAND: {filename}")
                try:
                    parsed = parse_command_file(filepath)
                    insert_parsed_commands(parsed)
                    cmd_count += len(parsed)
                except Exception as e:
                    print(f"    ERROR: {e}")

    print(f"  Found {cmd_count} commands, {tlm_count} telemetry packets")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Build cmd_tlm.sqlite database from COSMOS command/telemetry definition files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build from the OpenC3 COSMOS project's targets directory. This recurses
  # into every target's cmd_tlm/ folder (screens/ is skipped automatically):
  python build_database.py ../../../../gsw/cosmos-project/openc3-cosmos-cfs/targets

  # More than one directory may be given; each is searched recursively.
        """
    )
    parser.add_argument(
        'directories',
        nargs='+',
        help='One or more directories searched RECURSIVELY for COSMOS '
             'command/telemetry defs (cmd.txt/tlm.txt or *_cmd.txt/*_tlm.txt). '
             'Point this at the OpenC3 targets/ directory.'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Validate input directories
    for directory in args.directories:
        if not os.path.isdir(directory):
            print(f"Error: Directory not found: {directory}")
            exit(1)

    with app.app_context():
        # Rebuild from scratch each run so a stale build (e.g. the previous
        # NOS3 database) doesn't linger and get mixed with the new defs.
        db.drop_all()
        db.create_all()
        print("Created fresh database schema")

        # Process each given directory RECURSIVELY. This handles the OpenC3
        # layout (targets/<T>/cmd_tlm/*.txt) directly; the old NOS3-specific
        # "<dir>/components" + "<dir>/gsw" special-casing is no longer needed
        # since os.walk descends into whatever subdirectories exist.
        for directory in args.directories:
            print(f"\nProcessing: {directory}")
            process_directory_tree(directory)

        # Show summary statistics
        print("\n" + "="*60)
        print("Database Build Summary")
        print("="*60)
        cmd_count = db.session.query(Command).count()
        tlm_count = db.session.query(TelemetryPacket).count()
        print(f"Commands:  {cmd_count}")
        print(f"Telemetry: {tlm_count}")
        print("="*60)
