import socket
import sys
import threading
import time
import json
from collections import defaultdict, Counter
from datetime import datetime
import os

def get_output_folder():
    """Create and return the output folder path"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, 'output')
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def get_log_filename():
    """Generate a timestamped log filename"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = get_output_folder()
    return os.path.join(output_dir, f'anomaly_log_{timestamp}.txt')

class Logger:
    """Logger that writes to both console and file"""
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'w', encoding='utf-8')
        print(f"[✓] Logging to: {filename}\n")
    
    def write(self, message, console_only=False):
        """Write to both console and file"""
        print(message, end='')
        if not console_only:
            self.file.write(message)
            self.file.flush()  # Ensure immediate write
    
    def writeln(self, message='', console_only=False):
        """Write line to both console and file"""
        self.write(message + '\n', console_only)
    
    def close(self):
        """Close the log file"""
        self.file.close()

def listen_as_spacecop(host='127.0.0.1', port=9112):
    """
    Act as SpaceCOP listening on port 9112 for alerts from SpaceCOP ML
    This is the SERVER that LISTENS and accepts connections from SpaceCOP ML
    Now with statistics tracking and file logging!
    """
    log_file = get_log_filename()
    logger = Logger(log_file)

    logger.writeln(f"{'=' * 80}")
    logger.writeln(f"ANOMALY DETECTION SESSION LOG (SpaceCOP Simulator)")
    logger.writeln(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.writeln(f"Listening on: {host}:{port}")
    logger.writeln(f"{'=' * 80}\n")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)
    
    # Statistics tracking
    stats = {
        'total_alerts': 0,
        'by_type': defaultdict(int),  # CMD vs TLM
        'by_system': defaultdict(int),  # System names
        'by_mnemonic': Counter(),  # Mnemonics
        'responsible_features': Counter(),  # Which features cause anomalies
        'mse_values': [],  # MSE scores
        'start_time': time.time(),
        'first_alert_time': None,
        'last_alert_time': None,
    }
    
    def print_statistics():
        """Print accumulated statistics to both console and file"""
        output = []
        output.append("\n" + "=" * 80)
        output.append("ANOMALY DETECTION STATISTICS")
        output.append("=" * 80)
        
        if stats['total_alerts'] == 0:
            output.append("No alerts received yet.")
            for line in output:
                logger.writeln(line)
            return
        
        elapsed = time.time() - stats['start_time']
        alert_duration = (stats['last_alert_time'] - stats['first_alert_time']) if stats['first_alert_time'] else 0
        
        output.append(f"\n📊 SUMMARY:")
        output.append(f"  Total Alerts:        {stats['total_alerts']}")
        output.append(f"  Session Duration:    {elapsed:.1f}s")
        output.append(f"  Alert Rate:          {stats['total_alerts'] / elapsed:.2f} alerts/sec")
        if alert_duration > 0:
            output.append(f"  Alert Timespan:      {alert_duration:.1f}s")
        
        output.append(f"\n📈 MSE STATISTICS:")
        if stats['mse_values']:
            mse_sorted = sorted(stats['mse_values'])
            output.append(f"  Min MSE:             {min(stats['mse_values']):.6f}")
            output.append(f"  Max MSE:             {max(stats['mse_values']):.6f}")
            output.append(f"  Mean MSE:            {sum(stats['mse_values']) / len(stats['mse_values']):.6f}")
            output.append(f"  Median MSE:          {mse_sorted[len(mse_sorted)//2]:.6f}")
        
        output.append(f"\n🔍 BY DATA TYPE:")
        for data_type, count in sorted(stats['by_type'].items()):
            pct = (count / stats['total_alerts']) * 100
            output.append(f"  {data_type:10s}  {count:5d} ({pct:5.1f}%)")
        
        output.append(f"\n🎯 BY SYSTEM:")
        for system, count in sorted(stats['by_system'].items(), key=lambda x: -x[1])[:10]:
            pct = (count / stats['total_alerts']) * 100
            output.append(f"  {system:30s}  {count:5d} ({pct:5.1f}%)")
        if len(stats['by_system']) > 10:
            output.append(f"  ... and {len(stats['by_system']) - 10} more systems")
        
        output.append(f"\n📝 TOP 15 ALERT MNEMONICS:")
        for mnemonic, count in stats['by_mnemonic'].most_common(15):
            pct = (count / stats['total_alerts']) * 100
            output.append(f"  {mnemonic:50s}  {count:5d} ({pct:5.1f}%)")
        if len(stats['by_mnemonic']) > 15:
            output.append(f"  ... and {len(stats['by_mnemonic']) - 15} more mnemonics")
        
        output.append(f"\n⚠️  TOP 20 RESPONSIBLE FEATURES:")
        for feature, count in stats['responsible_features'].most_common(20):
            pct = (count / stats['total_alerts']) * 100
            output.append(f"  {feature:50s}  {count:5d} ({pct:5.1f}%)")
        if len(stats['responsible_features']) > 20:
            output.append(f"  ... and {len(stats['responsible_features']) - 20} more features")
        
        output.append("\n" + "=" * 80)
        output.append(f"Session ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append("=" * 80)
        
        for line in output:
            logger.writeln(line)

    try:
        server_socket.bind((host, port))
        server_socket.listen(1)
        logger.writeln(f"[✓] Listening on {host}:{port}")
        logger.writeln("Waiting for SpaceCOP ML to connect... Press Ctrl+C to show statistics and stop.\n")

        client_socket = None
        buffer = ""
        while True:
            try:
                # Accept connection if we don't have one
                if client_socket is None:
                    try:
                        client_socket, addr = server_socket.accept()
                        client_socket.settimeout(1.0)
                        buffer = ""  # Reset buffer for new connection
                        logger.writeln(f"[✓] SpaceCOP ML connected from {addr}\n")
                    except socket.timeout:
                        continue

                # Read data from connected client
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        logger.writeln("\n[!] SpaceCOP ML disconnected")
                        client_socket.close()
                        client_socket = None
                        buffer = ""  # Reset buffer on disconnect
                        logger.writeln("Waiting for reconnection...\n")
                        continue

                    # Decode and add to buffer
                    buffer += data.decode('utf-8', errors='replace')

                    # Process complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip():
                            try:
                                parsed = json.loads(line)

                                # Check if this is an actual alert (not welcome message)
                                if 'data' in parsed and 'anomaly_detection' in parsed:
                                    alert_data = parsed['data']
                                    anomaly_info = parsed['anomaly_detection']

                                    # Update statistics
                                    stats['total_alerts'] += 1

                                    # Track timing
                                    current_time = time.time()
                                    if stats['first_alert_time'] is None:
                                        stats['first_alert_time'] = current_time
                                    stats['last_alert_time'] = current_time

                                    # Track by type
                                    data_type = alert_data.get('data_type', 'UNKNOWN')
                                    stats['by_type'][data_type] += 1

                                    # Track by system
                                    system = alert_data.get('system', 'UNKNOWN')
                                    stats['by_system'][system] += 1

                                    # Track by mnemonic (full identifier)
                                    name = alert_data.get('name', 'UNKNOWN')
                                    mnemonic = f"{data_type}_{system}_{name}"
                                    stats['by_mnemonic'][mnemonic] += 1

                                    # Track responsible feature
                                    responsible = anomaly_info.get('responsible_feature', 'UNKNOWN')
                                    stats['responsible_features'][responsible] += 1

                                    # Track MSE
                                    mse = anomaly_info.get('mse', 0)
                                    stats['mse_values'].append(mse)

                                    # Print compact alert info
                                    threshold = anomaly_info.get('threshold', 0)
                                    alert_msg = f"[ALERT #{stats['total_alerts']:4d}] {mnemonic:50s} | MSE: {mse:8.6f} (>{threshold:.6f}) | Feature: {responsible:30s}"
                                    logger.writeln(alert_msg)

                                    # Print full JSON every 50th alert
                                    if stats['total_alerts'] % 50 == 0:
                                        logger.writeln(f"\n--- Alert #{stats['total_alerts']} Details ---")
                                        logger.writeln(json.dumps(parsed, indent=2))
                                        logger.writeln("-" * 80 + "\n")

                                elif 'status' in parsed:
                                    # Welcome/handshake message
                                    logger.writeln(f"[INFO] {parsed.get('message', 'Connected')}\n")

                            except json.JSONDecodeError:
                                logger.writeln(f"[RECEIVED] {line}")

                except socket.timeout:
                    # Timeout is OK, allows checking for Ctrl+C
                    continue

            except socket.timeout:
                # Outer timeout for accept()
                continue

    except OSError as e:
        if e.errno == 10048:  # Address already in use
            logger.writeln(f"[ERROR] Port {port} is already in use!")
            logger.writeln("Make sure no other instance is running on this port.")
        else:
            logger.writeln(f"[ERROR] OS Error: {e}")
    except KeyboardInterrupt:
        logger.writeln("\n[!] Shutting down SpaceCOP simulator...")
        print_statistics()
    except Exception as e:
        logger.writeln(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        logger.writeln(traceback.format_exc())
    finally:
        if client_socket:
            client_socket.close()
        server_socket.close()
        logger.writeln("\nServer stopped.")
        logger.close()
        print(f"\n[✓] Log saved to: {log_file}")


def send_mode(host='localhost', port=9111):
    """
    Send data to the specified port
    """
    print(f"Starting sender to {host}:{port}...")
    
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5.0)
    
    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")
        print("Type your hex messages (or 'quit' to exit):")
        print("Note: Each message will be sent with a newline\n")
        
        while True:
            # Get user input
            try:
                message = input("> ")
            except KeyboardInterrupt:
                print("\n[!] Shutting down sender...")
                break
            
            if message.lower() == 'quit':
                break
            
            if not message.strip():
                continue
            
            # Send the message WITH A NEWLINE
            client_socket.sendall((message + '\n').encode('utf-8'))
            print(f"[SENT] {message}")
            
    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to {host}:{port}. Is the server running?")
    except KeyboardInterrupt:
        print("\n[!] Shutting down sender...")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

def send_with_timestamp(message, timestamp=None):
    """Send hex with optional timestamp"""
    if timestamp is not None:
        return f"{timestamp},{message}"
    return message

def batch_send_mode(host='localhost', port=9111, filename=None):
    """
    Send multiple hex strings from a file or list
    """
    print(f"Starting batch sender to {host}:{port}...")
    
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5.0)
    
    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to {host}:{port}")
        
        if filename:
            # Read from file
            print(f"Reading hex strings from {filename}...")
            with open(filename, 'r') as f:
                lines = f.readlines()[1:]
        else:
            # Test data with timestamps
            base_time = time.time()
            lines = [
                f"{base_time},0x1926C00000010000",
                f"{base_time + 1.5},1992c00000040300020500",
                f"{base_time + 3.2},1871c00000000100",
                f"{base_time + 5.0},18c9c00000010000",
            ]
        
        print(f"Sending {len(lines)} messages...\n")
        
        for i, line in enumerate(lines, 1):
            message = line.strip()
            if not message or message.startswith('#'):
                continue
            
            # Send with newline
            client_socket.sendall((message + '\n').encode('utf-8'))
            print(f"[{i}/{len(lines)}] Sent: {message}")
            
            # Small delay to allow processing
            time.sleep(.001)
        
        print("\n[✓] All messages sent successfully!")
        
    except ConnectionRefusedError:
        print(f"[ERROR] Could not connect to {host}:{port}. Is the server running?")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()
        print("Connection closed.")


def integrated_test(host='localhost'):
    """
    Run both SpaceCOP listener and sender in one script
    """
    print("=" * 60)
    print("Integrated Test Mode")
    print("=" * 60)
    print("\nThis will:")
    print("1. Start SpaceCOP simulator listening on port 9112 (in background)")
    print("2. Let you send hex messages to port 9111 (SpaceCOP ML)")
    print("=" * 60)

    # Start SpaceCOP listener in background thread
    listener_thread = threading.Thread(
        target=listen_as_spacecop,
        args=(host, 9112),
        daemon=True
    )
    listener_thread.start()

    # Give listener time to start
    time.sleep(1)

    # Now run sender in main thread
    print("\n" + "=" * 60)
    send_mode(host=host, port=9111)


def main():
    """
    Main function to choose between modes
    """
    print("=" * 60)
    print("SpaceCOP ML Test Script")
    print("=" * 60)
    print("\nChoose mode:")
    print("1. Act as SpaceCOP (listen on port 9112) - RECOMMENDED FIRST")
    print("2. Send hex data to SpaceCOP ML (port 9111)")
    print("3. Batch send test data (port 9111)")
    print("4. Batch send from file (port 9111)")
    print("5. Integrated test (SpaceCOP listener + hex sender)")
    print("=" * 60)

    choice = input("\nEnter your choice (1-5): ").strip()

    host = input("Enter target host (default: localhost): ").strip() or 'localhost'

    if choice == '1':
        listen_as_spacecop(host=host)
    elif choice == '2':
        send_mode(host=host)
    elif choice == '3':
        batch_send_mode(host=host)
    elif choice == '4':
        filename = input("Enter filename: ").strip()
        batch_send_mode(host=host, filename=filename)
    elif choice == '5':
        integrated_test(host=host)
    else:
        print("[ERROR] Invalid choice. Please run the script again.")
        sys.exit(1)


if __name__ == "__main__":
    main()