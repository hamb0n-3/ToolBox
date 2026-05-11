#!/usr/bin/env python3
"""
RabbitMQ verification script.
Usage:
  rabbitmq_verify.py <IP> [<IP> ...]       # One or more IPs directly
  rabbitmq_verify.py -iL <file>            # Load IPs from a file (nmap-style)
  rabbitmq_verify.py <IP> -iL <file>       # Mix of both
"""

import argparse
import sys
import socket
import logging
from datetime import datetime, timezone

try:
    import amqp
except ImportError:
    print("[!] Missing dependency: pip install amqp")
    sys.exit(1)


def parse_ip_file(filepath: str) -> list[str]:
    """Read IPs/hostnames from a file, one per line. Ignores blank lines and comments."""
    try:
        with open(filepath, "r") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Permission denied reading: {filepath}")
        sys.exit(1)


def verify_host(host: str, port: int = 5672) -> dict:
    """
    Attempt an anonymous (guest:guest) AMQP connection to host:port.
    Returns a result dict with keys: host, port, success, mechanisms, properties, error.
    """
    result = {
        "host": host,
        "port": port,
        "success": False,
        "mechanisms": None,
        "properties": {},
        "error": None,
    }
    try:
        conn = amqp.connection.Connection(
            host=host,
            port=port,
            virtual_host="/",
            connect_timeout=5,
        )
        conn.connect()
        result["success"] = True
        result["mechanisms"] = conn.mechanisms
        result["properties"] = dict(conn.server_properties)
        try:
            conn.close()
        except Exception:
            pass
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)
    return result


def print_result(result: dict) -> None:
    host_label = f"{result['host']}:{result['port']}"
    if result["success"]:
        print(f"\n[+] {host_label}  —  OPEN / anonymous login succeeded")
        if result["mechanisms"]:
            print(f"    SASL mechanisms : {result['mechanisms']}")
        if result["properties"]:
            print("    Server properties:")
            for k, v in result["properties"].items():
                print(f"      {k}: {v}")
    else:
        print(f"[-] {host_label}  —  FAILED ({result['error']})")


def setup_logger(logfile: str) -> logging.Logger:
    """Configure a file logger that appends one line per host."""
    logger = logging.getLogger("rabbitmq_verify")
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(logfile, mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def log_result(logger: logging.Logger, result: dict) -> None:
    """Append a single structured line to the logfile immediately after each host is checked."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    host_label = f"{result['host']}:{result['port']}"
    if result["success"]:
        mechanisms = result["mechanisms"] or ""
        version = result["properties"].get("version", "unknown")
        product = result["properties"].get("product", "unknown")
        logger.info(
            f"{ts}  VULNERABLE  {host_label}  "
            f"product={product}  version={version}  mechanisms={mechanisms}"
        )
    else:
        logger.info(
            f"{ts}  NOT_VULNERABLE  {host_label}  reason={result['error']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Verify RabbitMQ anonymous access (guest:guest) on one or more hosts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "ips",
        nargs="*",
        metavar="IP",
        help="One or more IP addresses or hostnames",
    )
    parser.add_argument(
        "-iL",
        dest="ip_file",
        metavar="FILE",
        help="File containing IPs/hostnames, one per line (nmap-style)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5672,
        metavar="PORT",
        help="AMQP port (default: 5672)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a summary table at the end",
    )
    parser.add_argument(
        "--log",
        metavar="FILE",
        default="rabbitmq_verify.log",
        help="Logfile to append results to (default: rabbitmq_verify.log)",
    )

    args = parser.parse_args()

    targets: list[str] = list(args.ips)
    if args.ip_file:
        targets.extend(parse_ip_file(args.ip_file))

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_targets: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)

    if not unique_targets:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Scanning {len(unique_targets)} host(s) on port {args.port} ...")
    print(f"[*] Logging results to: {args.log}")

    logger = setup_logger(args.log)
    logger.info(f"# Scan started {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  targets={len(unique_targets)}  port={args.port}")

    results = []
    for host in unique_targets:
        result = verify_host(host, args.port)
        print_result(result)
        log_result(logger, result)
        results.append(result)

    if args.summary or len(unique_targets) > 1:
        open_hosts  = [r for r in results if r["success"]]
        closed_hosts = [r for r in results if not r["success"]]
        print(f"\n{'='*50}")
        print(f"  Summary: {len(open_hosts)} open / {len(closed_hosts)} closed out of {len(results)} scanned")
        if open_hosts:
            print("  Vulnerable hosts:")
            for r in open_hosts:
                print(f"    {r['host']}:{r['port']}")
        print(f"{'='*50}")

    logger.info(f"# Scan finished {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  vulnerable={len([r for r in results if r['success']])}  total={len(results)}")


if __name__ == "__main__":
    main()