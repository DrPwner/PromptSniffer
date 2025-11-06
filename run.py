#!/usr/bin/env python3
"""
PromptSniffer Launcher
Starts the network-wide LLM prompt monitoring system
"""

import json
import os
import socket
import subprocess
import sys
from pathlib import Path


def print_banner():
    """Print startup banner"""
    print("""
===============================================================
                      PromptSniffer
              Network-Wide LLM Prompt Monitor
===============================================================
""")


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_config():
    """Verify configuration"""
    config_path = Path("config.json")

    if not config_path.exists():
        print("[ERROR] config.json not found!")
        print("Run setup.py first: python setup.py")
        sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid config.json: {e}")
        sys.exit(1)

    # Check if app password is configured
    if config['email']['app_password'] == "YOUR_GMAIL_APP_PASSWORD_HERE":
        print("[ERROR] Gmail App Password not configured!")
        print("Edit config.json and set your Gmail App Password")
        print("\nTo get an App Password:")
        print("1. Go to https://myaccount.google.com/apppasswords")
        print("2. Create a new app password for 'Mail'")
        print("3. Copy the 16-character password")
        print("4. Replace 'YOUR_GMAIL_APP_PASSWORD_HERE' in config.json")
        sys.exit(1)

    return config


def check_admin_rights():
    """Check if running with appropriate privileges"""
    if sys.platform == 'win32':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("[WARNING] Not running as Administrator")
                print("For best results, run as Administrator for network-wide monitoring")
                print("\nContinuing anyway...\n")
        except Exception:
            pass
    else:
        if os.geteuid() != 0:
            print("[WARNING] Not running as root")
            print("For best results, run with sudo for network-wide monitoring")
            print("\nContinuing anyway...\n")


def display_info(config):
    """Display monitoring information"""
    local_ip = get_local_ip()

    print("[*] Configuration:")
    print(f"    Local IP: {local_ip}")
    print(f"    Proxy Port: 8080")
    print(f"    Log File: {config['monitoring']['log_file']}")
    print(f"    Email Recipients: {', '.join(config['email']['recipients'])}")
    print(f"    Monitoring {len([d for domains in config['llm_endpoints'].values() for d in domains])} LLM domains")

    print("\n[*] Target devices should configure proxy:")
    print(f"    HTTP Proxy: {local_ip}:8080")
    print(f"    HTTPS Proxy: {local_ip}:8080")

    print("\n[*] Certificate installation:")
    print(f"    Visit http://mitm.it on target devices to install certificate")

    print("\n" + "=" * 60)
    print("Starting PromptSniffer...")
    print("Press Ctrl+C to stop")
    print("=" * 60 + "\n")


def start_monitoring():
    """Start mitmproxy with the interceptor addon"""
    try:
        # Try to find mitmdump
        mitmdump_cmd = None

        # On Windows, check user Scripts folder first
        if sys.platform == 'win32':
            # Check user Scripts folder
            user_scripts = Path(os.path.expanduser("~")) / "AppData" / "Roaming" / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts" / "mitmdump.exe"
            if user_scripts.exists():
                mitmdump_cmd = str(user_scripts)
            else:
                # Try PATH
                try:
                    result = subprocess.run(["where", "mitmdump"],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        mitmdump_cmd = result.stdout.strip().split('\n')[0]
                except Exception:
                    pass
        else:
            # Linux/Mac: use PATH
            mitmdump_cmd = "mitmdump"

        if not mitmdump_cmd:
            print("[ERROR] mitmdump not found!")
            print("Install it with: python -m pip install mitmproxy")
            sys.exit(1)

        # Build command
        cmd = [
            mitmdump_cmd,
            "-s", "prompt_interceptor.py",
            "--listen-host", "0.0.0.0",
            "--listen-port", "8080",
            "--set", "flow_detail=1",
            "--set", "block_global=false"
        ]

        print(f"[*] Using mitmdump: {mitmdump_cmd}\n")

        # Start mitmproxy
        subprocess.run(cmd)

    except FileNotFoundError:
        print("[ERROR] mitmproxy not found!")
        print("Install it with: python -m pip install mitmproxy")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[*] PromptSniffer stopped by user")
        print("[*] Check prompt_sniffer.log for captured prompts")
        sys.exit(0)


def main():
    """Main launcher function"""
    try:
        print_banner()
        config = check_config()
        check_admin_rights()
        display_info(config)
        start_monitoring()

    except KeyboardInterrupt:
        print("\n\n[*] Cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
