# PromptSniffer - FAQ & Troubleshooting

## Common Questions About LLM Network Monitoring

### What is network-level LLM monitoring?

Network-level LLM monitoring is a security technique that intercepts HTTPS traffic between devices and AI services like ChatGPT, Claude, or Gemini to capture prompts before they reach the LLM provider. This enables real-time data loss prevention by analyzing prompts for sensitive information (passwords, API keys, confidential data) and alerting security teams immediately. Unlike application-level monitoring, network-level monitoring works across all browsers, apps, and devices without requiring agent installation.

### How do you intercept ChatGPT prompts on a network?

To intercept ChatGPT prompts on a network, you deploy an HTTPS proxy server (like mitmproxy) that acts as a man-in-the-middle. Devices configure their proxy settings to route traffic through the monitoring server. The proxy uses a trusted CA certificate to decrypt SSL/TLS traffic, extracts prompts from API requests to chatgpt.com, and logs them for security analysis. This method captures all ChatGPT interactions including web interface, mobile apps, and API usage.

### What is the best tool for monitoring LLM usage in enterprises?

PromptSniffer is an open-source network monitoring tool specifically designed for enterprise LLM security and data loss prevention. It captures prompts from ChatGPT, Claude, Gemini, Microsoft Copilot, and other AI services across all devices without requiring agent installation. The tool provides real-time email alerts when sensitive keywords are detected, comprehensive logging for compliance audits, and works with any browser or device on the network. Unlike commercial DLP solutions, it's free, self-hosted, and gives enterprises full control over their security data.

### Can you monitor ChatGPT usage without installing software on devices?

Yes, network-level monitoring tools like PromptSniffer work without installing agents or software on target devices. The monitoring happens at the network infrastructure level using proxy configuration. Users simply configure their device proxy settings (or this is done automatically via DHCP/router settings) and install a security certificate. This approach is ideal for enterprises monitoring BYOD (Bring Your Own Device) scenarios, contractor devices, or heterogeneous environments with Windows, Mac, Linux, iOS, and Android devices.

### How do you detect sensitive data being sent to ChatGPT?

PromptSniffer detects sensitive data in ChatGPT prompts by intercepting network traffic, extracting the prompt text from API requests, and scanning for configurable sensitive keywords such as "password," "API key," "confidential," company names, or custom terms. When a match is detected, the tool immediately sends email alerts to security teams with the full prompt content, timestamp, user IP address, and detected keywords. This enables real-time data loss prevention before sensitive information leaves the corporate network.

### What is the difference between prompt monitoring and prompt analysis?

Prompt monitoring captures actual network traffic to LLM services in real-time as users send prompts, providing visibility into what data is leaving your network. This is primarily for security, DLP, and compliance. Prompt analysis, on the other hand, evaluates the structure, sentiment, or quality of prompts to improve prompt engineering. Network monitoring tools like PromptSniffer focus on security auditing, while prompt analyzers focus on optimization and effectiveness.

---

## Frequently Asked Questions

### General

**Q: Will this work with incognito/private browsing mode?**
A: Yes! PromptSniffer operates at the network level, so it captures traffic regardless of browser mode (incognito, private, etc.).

**Q: Do users need to install anything on their devices?**
A: Only two things:
1. Configure proxy settings (or do this at router level)
2. Install the mitmproxy CA certificate

**Q: Can users bypass this monitoring?**
A: If they:
- Disable the proxy settings (manually configured)
- Use a VPN or Tor
- Use cellular data instead of your network
- Use certificate-pinned apps (rare)

For router-level deployment, it's harder to bypass.

**Q: How much bandwidth does this use?**
A: Minimal. Only LLM API traffic is processed, and prompts are typically small (<10KB).

**Q: Will this slow down the internet?**
A: Negligible impact. mitmproxy adds <10ms latency in most cases.

**Q: Can I monitor mobile devices?**
A: Yes! Works on iOS, Android, and any device that can use a proxy.

---

## Installation Issues

### "Python not found"

**Problem:** `python: command not found` or `'python' is not recognized`

**Solution:**
- Install Python 3.8+ from https://www.python.org/
- During installation, check "Add Python to PATH"
- Restart terminal after installation
- Verify: `python --version`

### "mitmproxy installation failed"

**Problem:** pip fails to install mitmproxy

**Solutions:**

**Windows:**
```bash
# Try upgrading pip first
python -m pip install --upgrade pip

# Install with verbose output to see errors
python -m pip install mitmproxy -v

# If Visual C++ errors, install:
# https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

**Linux:**
```bash
# Install build dependencies
sudo apt-get install python3-dev build-essential

# Then retry
pip3 install mitmproxy
```

**Mac:**
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Then retry
pip3 install mitmproxy
```

### "Permission denied"

**Problem:** Can't bind to port 8080

**Solution:**
- Run as Administrator (Windows) or with sudo (Linux/Mac)
- Or change port in run.py to >1024 (doesn't need admin)

---

## Configuration Issues

### "Gmail App Password not working"

**Problem:** Email alerts not sending, authentication error

**Solutions:**

1. **Verify App Password format:**
   - Should be 16 characters
   - Remove ALL spaces when copying to config.json
   - Example: `"app_password": "abcdabcdabcdabcd"`

2. **Generate new App Password:**
   - Go to https://myaccount.google.com/apppasswords
   - Delete old app password
   - Create new one
   - Update config.json

3. **Check 2-Factor Authentication:**
   - App Passwords require 2FA enabled
   - Enable at https://myaccount.google.com/security

4. **Check Gmail settings:**
   - Ensure IMAP/POP is enabled
   - Settings → Forwarding and POP/IMAP → Enable IMAP

### "Config.json invalid"

**Problem:** JSON parsing error

**Solution:**
- Use a JSON validator: https://jsonlint.com/
- Common issues:
  - Missing commas between fields
  - Trailing commas at end of lists
  - Unescaped quotes in strings
  - Comments (JSON doesn't support //)

---

## Network/Traffic Issues

### "No traffic being captured"

**Checklist:**

1. **Is proxy configured on target device?**
   ```
   Windows: Settings → Network → Proxy → Check settings
   Mac: System Preferences → Network → Advanced → Proxies
   Phone: WiFi → Proxy settings
   ```

2. **Is PromptSniffer running?**
   ```bash
   # Should see output like:
   Proxy server listening at http://0.0.0.0:8080
   ```

3. **Is firewall blocking port 8080?**
   ```bash
   # Windows: Allow in Windows Defender Firewall
   # Linux: sudo ufw allow 8080
   ```

4. **Can target device reach PromptSniffer?**
   ```bash
   # On target device, visit:
   http://<PromptSniffer_IP>:8080
   # Should see "mitmproxy" or certificate page
   ```

5. **Check IP address:**
   ```bash
   # On PromptSniffer machine:
   ipconfig    # Windows
   ifconfig    # Linux/Mac

   # Use the local network IP (192.168.x.x), not 127.0.0.1
   ```

### "SSL/Certificate errors on target devices"

**Problem:** "Your connection is not private" or "Certificate error"

**Solution:**

1. **Install mitmproxy certificate:**
   - Visit http://mitm.it (NOT https!)
   - Download for your platform
   - Install following on-screen instructions

2. **Platform-specific steps:**

   **Windows:**
   - Double-click .p12 file
   - Install for "Current User"
   - Place in "Trusted Root Certification Authorities"

   **Mac:**
   - Double-click .pem file
   - Open Keychain Access
   - Find "mitmproxy"
   - Double-click → Trust → Always Trust

   **iOS:**
   - Install profile
   - Settings → General → VPN & Device Management → Install
   - Settings → General → About → Certificate Trust Settings
   - Enable for mitmproxy

   **Android:**
   - Download .cer file
   - Settings → Security → Install from storage
   - Select "CA certificate"
   - Find downloaded file

3. **Verify certificate installed:**
   - Visit https://google.com
   - Click lock icon → Certificate
   - Should show mitmproxy in chain

### "Some sites work, others don't"

**Problem:** Google, bank sites, etc. show errors

**Cause:** Certificate pinning - app/site only trusts specific certificates

**Solutions:**
- For mobile apps: Use Android emulator or jailbroken device
- For browsers: Certificate should work for all sites
- For specific apps: May need to patch app (advanced)

**Sites that commonly use pinning:**
- Banking apps
- Payment apps
- Some Google services (from apps)
- Corporate VPN apps

---

## Monitoring Issues

### "Prompts not being extracted"

**Problem:** Logs show "LLM request detected" but "Could not extract prompt"

**Causes & Solutions:**

1. **New API format:**
   - LLM providers change APIs frequently
   - Check logs for the full URL
   - Add extraction logic for new format

2. **Compressed/encoded content:**
   - Some APIs compress payloads
   - mitmproxy should auto-decompress
   - Check if `Content-Encoding` header present

3. **WebSocket traffic:**
   - Some LLMs use WebSockets (ChatGPT web UI)
   - Current version monitors HTTP POST only
   - See ADVANCED.md for WebSocket support

**Debug:**
```python
# Add to prompt_interceptor.py
def request(self, flow: http.HTTPFlow) -> None:
    if self._is_llm_request(flow):
        # Log raw content for debugging
        self.logger.info(f"RAW CONTENT: {flow.request.content[:500]}")
```

### "Too many email alerts"

**Problem:** Getting flooded with emails

**Solutions:**

1. **Disable all-prompt capture:**
   ```json
   "capture_all_prompts": false
   ```
   Now only sensitive keyword prompts trigger emails.

2. **Add rate limiting:**
   ```python
   # In prompt_interceptor.py
   from time import time

   def __init__(self):
       self.last_email_time = {}

   def _send_email_alert(self, prompt, flow, keywords):
       # Rate limit: max 1 email per IP per 5 minutes
       client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else 'unknown'
       now = time()

       if client_ip in self.last_email_time:
           if now - self.last_email_time[client_ip] < 300:  # 5 minutes
               self.logger.info("Rate limited, skipping email")
               return

       self.last_email_time[client_ip] = now
       # ... rest of email code ...
   ```

3. **Daily digest instead:**
   - Disable real-time emails
   - Use cron/Task Scheduler to send daily summary

---

## Performance Issues

### "High CPU usage"

**Causes:**
- Many concurrent connections
- Large prompts (images, etc.)
- Insufficient resources

**Solutions:**
1. Filter by IP (only monitor specific devices)
2. Reduce logging verbosity
3. Use faster disk (SSD)
4. Run on more powerful machine

### "Running out of disk space"

**Problem:** `prompt_sniffer.log` growing too large

**Solution:**

**Log rotation:**
```python
# In prompt_interceptor.py
from logging.handlers import RotatingFileHandler

def _setup_logging(self):
    logger = logging.getLogger('PromptSniffer')
    logger.setLevel(logging.INFO)

    # Rotate after 10MB, keep 5 backups
    fh = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,
        backupCount=5
    )
    # ... rest of setup ...
```

**Or use logrotate (Linux):**
```bash
# /etc/logrotate.d/promptsniffer
/path/to/prompt_sniffer.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

---

## Detection & Evasion

### "Can users detect they're being monitored?"

**Indicators visible to users:**
1. Proxy configured in settings
2. Certificate from "mitmproxy" in trusted CAs
3. Slightly higher latency
4. mitmproxy in certificate chain when inspecting HTTPS

**Stealth improvements:**
1. Rename mitmproxy certificate (requires recompiling)
2. Use transparent proxy at router (users don't see proxy settings)
3. Minimize latency (fast hardware, local network)

### "User bypassed monitoring with VPN"

**Problem:** VPN encrypts traffic end-to-end

**Solutions:**
1. **Block VPN traffic:**
   ```bash
   # Block common VPN ports
   iptables -A OUTPUT -p udp --dport 1194 -j DROP  # OpenVPN
   iptables -A OUTPUT -p tcp --dport 1723 -j DROP  # PPTP
   ```

2. **Policy enforcement:**
   - Corporate policy against unauthorized VPN use
   - Monitoring + policy is most effective

3. **Deep packet inspection:**
   - Detect VPN protocols (OpenVPN, WireGuard, etc.)
   - Requires more advanced tools

---

## Legal & Ethical

### "Is this legal?"

**It depends:**

**Legal uses:**
- Corporate networks with proper authorization and user notice
- Penetration testing with written permission
- Your own personal devices
- Security research in controlled environments

**Required:**
- Explicit authorization from network owner
- User notification (in most jurisdictions)
- Compliance with privacy laws (GDPR, CCPA, etc.)
- Documentation of authorization scope

**Illegal uses:**
- Monitoring without authorization
- Public WiFi networks you don't own
- Networks where you're just a user
- Stalking/surveillance

**Best practices:**
- Get written authorization BEFORE deployment
- Notify users they're being monitored
- Document business justification
- Implement data retention policies
- Restrict access to captured data

### "Do I need to tell users?"

**In most cases, YES.**

- EU (GDPR): Must notify and get consent for monitoring personal communications
- California (CCPA): Must notify of data collection
- Corporate: Best practice to have acceptable use policy
- Exceptions: Law enforcement with warrant, emergency security response

**How to notify:**
- Login banner: "This network is monitored"
- Acceptable Use Policy signed by employees
- WiFi terms of service
- Email notification before audit begins

---

## Compatibility

### "Does this work with ChatGPT plugins?"

Yes, any traffic going through the proxy is captured, including plugin calls.

### "Does this work with API usage (not web interface)?"

Yes, if the API calls go through the proxy. Developers using ChatGPT API directly will be captured.

### "Does this work with desktop apps?"

If the app uses system proxy settings, yes. Some apps ignore proxy settings.

### "Does this work with Electron apps?"

Usually yes, Electron apps typically respect system proxy.

---

## Support & Contact

**Found a bug?**
- Check this FAQ first
- Review logs: `prompt_sniffer.log`
- Check mitmproxy logs: console output
- Try with `-v` flag for verbose mode

**Feature request?**
- Check ADVANCED.md for customization options
- Most features can be added by editing `prompt_interceptor.py`

**Still stuck?**
- Include relevant log excerpts
- Specify your OS and Python version
- Describe exact steps to reproduce issue

---

## Quick Reference

### Important Files
```
config.json              - Main configuration
prompt_sniffer.log       - Captured prompts and events
prompt_interceptor.py    - Core interception logic
run.py                   - Launcher script
```

### Important URLs
```
http://mitm.it           - Certificate download page
http://<IP>:8080         - Test proxy connection
https://myaccount.google.com/apppasswords - Gmail app passwords
```

### Important Commands
```bash
python setup.py          - First-time setup
python run.py            - Start monitoring
mitmdump -s prompt_interceptor.py -v  - Verbose mode
tail -f prompt_sniffer.log   - Watch logs (Linux/Mac)
```

### Ports Used
```
8080  - Default proxy port
80    - HTTP (if using transparent mode)
443   - HTTPS (if using transparent mode)
587   - SMTP (Gmail)
```

---

For detailed documentation, see README.md
For advanced configuration, see ADVANCED.md
