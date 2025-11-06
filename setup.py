"""
PromptSniffer Setup Script
Installs dependencies and configures the proxy
"""

import json
import subprocess
import sys
from pathlib import Path


def print_banner():
    """Print setup banner"""
    print("""
===============================================================
                    PromptSniffer Setup
              Network-Wide LLM Prompt Monitor
===============================================================
""")


def check_python_version():
    """Ensure Python 3.8+"""
    if sys.version_info < (3, 8):
        print("[ERROR] Python 3.8 or higher is required")
        sys.exit(1)
    print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")


def install_dependencies():
    """Install required packages"""
    print("\n[*] Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("[OK] Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to install dependencies: {e}")
        sys.exit(1)


def configure_email():
    """Configure email settings"""
    print("\n[*] Email Configuration")
    print("=" * 60)

    config_path = Path("config.json")
    with open(config_path, 'r') as f:
        config = json.load(f)

    print("\nCurrent configuration:")
    print(f"  Sender: {config['email']['sender']}")
    print(f"  Recipients: {', '.join(config['email']['recipients'])}")

    # Check if app password is set
    if config['email']['app_password'] == "YOUR_GMAIL_APP_PASSWORD_HERE":
        print("\n[WARNING] Gmail App Password not configured!")
        print("\nTo configure:")
        print("1. Go to https://myaccount.google.com/apppasswords")
        print("2. Create a new app password for 'Mail'")
        print("3. Copy the 16-character password")
        print("4. Edit config.json and replace 'YOUR_GMAIL_APP_PASSWORD_HERE'")
        print("   with your app password")
        print("\n[!] You must configure this before running PromptSniffer")
    else:
        print("[OK] Gmail App Password is configured")

    # Ask about recipients
    print("\n[?] Do you want to add a second recipient? (y/n): ", end='')
    response = input().strip().lower()

    if response == 'y':
        print("Enter second recipient email: ", end='')
        second_email = input().strip()
        if second_email and '@' in second_email:
            config['email']['recipients'].append(second_email)
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"[OK] Added {second_email} as recipient")
        else:
            print("[ERROR] Invalid email address")


def display_certificate_info():
    """Display information about certificate installation"""
    print("\n" + "=" * 60)
    print("CERTIFICATE INSTALLATION REQUIRED")
    print("=" * 60)
    print("""
To intercept HTTPS traffic, you must install mitmproxy's CA certificate
on all devices you want to monitor.

STEPS:

1. Start PromptSniffer (it will run mitmproxy)

2. On each target device:
   a. Configure proxy settings:
      - Proxy: <IP of this machine>
      - Port: 8080

   b. Visit http://mitm.it in a browser

   c. Download and install the certificate for your OS:
      - Windows: Click "Windows", run the .p12 file
      - Mac: Click "Apple", install the .pem file
      - iOS: Click "Apple", install profile, enable in Settings
      - Android: Click "Android", install as CA certificate

3. The certificate allows PromptSniffer to decrypt HTTPS traffic

IMPORTANT: This is REQUIRED for the tool to work!

For network-wide monitoring:
- Configure your router's DHCP to use this machine as proxy
- Or use ARP spoofing (requires additional tools)
- Or configure each device manually

""")


def display_usage():
    """Display usage instructions"""
    print("=" * 60)
    print("SETUP COMPLETE!")
    print("=" * 60)
    print("""
Next steps:

1. Edit config.json and add your Gmail App Password

2. Run PromptSniffer:
   python run.py

   Or on Linux/Mac:
   ./run.py

3. Configure target devices to use this proxy:
   - IP: <this machine's IP>
   - Port: 8080

4. Install mitmproxy certificate on target devices (visit http://mitm.it)

5. Monitor the logs:
   - Console output: Real-time monitoring
   - Log file: prompt_sniffer.log
   - Email alerts: Sent for each detected prompt

For help: Check README.md
""")


def main():
    """Main setup function"""
    try:
        print_banner()
        check_python_version()
        install_dependencies()
        configure_email()
        display_certificate_info()
        display_usage()

    except KeyboardInterrupt:
        print("\n\n[*] Setup cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
