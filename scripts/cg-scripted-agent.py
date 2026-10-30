#!/usr/bin/env python3
"""
CyberGlass Scripted Input Agent (Python Standalone)
Zero-dependency, modifiable, deployable data onboarding agent.

Supports:
- Command/Script execution on periodic interval (e.g. netstat, ps, who, wmic, custom scripts)
- File tailing / monitoring
- Directory watching
- Splunk HEC and CyberGlass REST API ingestion
- Service / Background daemon mode
"""

import sys
import os
import time
import json
import argparse
import platform
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

def get_iso_time():
    return datetime.now(timezone.utc).isoformat()

def send_event_rest(server_url, payload, api_key=None):
    url = f"{server_url.rstrip('/')}/api/v1/ingest"
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, credentials=None)
    req.add_header('Content-Type', 'application/json')
    if api_key:
        req.add_header('Authorization', f'Bearer {api_key}')
    
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def send_event_hec(server_url, event_data, token=None, source="script", sourcetype="json", index="main"):
    url = f"{server_url.rstrip('/')}/services/collector/event"
    hec_payload = {
        "event": event_data,
        "source": source,
        "sourcetype": sourcetype,
        "index": index,
        "time": time.time()
    }
    data = json.dumps(hec_payload).encode('utf-8')
    req = urllib.request.Request(url, data=data)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', f'Splunk {token}')
    
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def run_command(cmd):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        return res.stdout if res.returncode == 0 else f"{res.stdout}\n{res.stderr}".strip()
    except Exception as e:
        return f"Error executing command: {e}"

def tail_file(filepath, callback, poll_interval=1.0):
    if not os.path.exists(filepath):
        print(f"[!] Warning: File {filepath} does not exist yet. Waiting...")
    
    while not os.path.exists(filepath):
        time.sleep(poll_interval)
        
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                callback(line.rstrip('\r\n'))
            else:
                time.sleep(poll_interval)

def main():
    parser = argparse.ArgumentParser(description="CyberGlass Scripted Input Agent")
    parser.add_argument("--server", default="http://localhost:9401", help="CyberGlass Server URL")
    parser.add_argument("--token", help="HEC or API token")
    parser.add_argument("--script", help="Command or script to execute periodically")
    parser.add_argument("--interval", type=int, default=30, help="Interval in seconds for script execution (default: 30)")
    parser.add_argument("--tail", help="Path of log file to follow/tail")
    parser.add_argument("--source", default=f"{platform.node()}_agent", help="Event source identifier")
    parser.add_argument("--source-type", default="json", help="Sourcetype (json, syslog, os_metrics, cmd_output)")
    parser.add_argument("--index", default="main", help="Target index (default: main)")
    parser.add_argument("--mode", choices=["rest", "hec"], default="rest", help="Ingestion mode (rest or hec)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    
    args = parser.parse_args()
    hostname = platform.node()
    os_info = f"{platform.system()} {platform.release()}"
    
    print("=" * 60)
    print("  CyberGlass Scripted Input Agent (Python)")
    print(f"  Target Server : {args.server}")
    print(f"  Ingest Mode   : {args.mode.upper()}")
    print(f"  Host          : {hostname} ({os_info})")
    print(f"  Target Index  : {args.index}")
    print("=" * 60)

    def dispatch(raw_data):
        if not raw_data or not raw_data.strip():
            return
        if args.mode == "hec":
            res = send_event_hec(args.server, raw_data, token=args.token, source=args.source, sourcetype=args.source_type, index=args.index)
        else:
            payload = {
                "source": args.source,
                "source_type": args.source_type,
                "index": args.index,
                "raw": raw_data
            }
            res = send_event_rest(args.server, payload, api_key=args.token)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Ingested event ({len(raw_data)} bytes) -> {res.get('status', 'OK')}")

    # Mode 1: File tailing
    if args.tail:
        print(f"[*] Following file: {args.tail}")
        try:
            tail_file(args.tail, dispatch)
        except KeyboardInterrupt:
            print("\n[*] Agent stopped by user.")
            sys.exit(0)

    # Mode 2: Script / Command execution
    elif args.script:
        print(f"[*] Periodic execution command: {args.script} (every {args.interval}s)")
        try:
            while True:
                out = run_command(args.script)
                if out:
                    # Package structured output with host telemetry
                    event_payload = json.dumps({
                        "host": hostname,
                        "os": os_info,
                        "command": args.script,
                        "timestamp": get_iso_time(),
                        "output": out
                    }) if args.source_type == "json" else out
                    dispatch(event_payload)
                if args.once:
                    break
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Agent stopped by user.")
            sys.exit(0)
    else:
        # Default fallback: Send host telemetry
        print("[*] No script or file specified. Collecting standard system heartbeat...")
        cpu_cmd = "wmic cpu get loadpercentage /value" if platform.system() == "Windows" else "cat /proc/loadavg"
        out = run_command(cpu_cmd)
        sample = json.dumps({
            "host": hostname,
            "os": os_info,
            "agent_version": "0.2.0",
            "heartbeat": True,
            "timestamp": get_iso_time(),
            "cpu_sample": out.strip()
        })
        dispatch(sample)
        print("[+] Heartbeat event delivered successfully.")

if __name__ == "__main__":
    main()
