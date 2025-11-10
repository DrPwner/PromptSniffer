# PromptSniffer

**Network-Wide LLM Prompt Monitoring & Data Loss Prevention Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![mitmproxy](https://img.shields.io/badge/mitmproxy-12.0+-green.svg)](https://mitmproxy.org/)
[![Stars](https://img.shields.io/github/stars/DrPwner/PromptSniffer?style=social)](https://github.com/DrPwner/PromptSniffer/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/DrPwner/PromptSniffer)](https://github.com/DrPwner/PromptSniffer/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-contributing)

## What is PromptSniffer?

PromptSniffer is a **network security auditing tool** and **data loss prevention (DLP) solution** that intercepts and monitors prompts sent to Large Language Models like ChatGPT, Claude, and Gemini across your entire network. Unlike metadata extractors or prompt analyzers, PromptSniffer operates at the network level using HTTPS interception to capture real-time LLM API traffic.

**Use Cases:**
- 🏢 Corporate Data Loss Prevention (DLP) monitoring
- 🔒 Authorized penetration testing engagements
- 🔬 Security research in controlled environments
- 📋 Compliance auditing (GDPR, CCPA, HIPAA)
- 🚨 Insider threat detection
- 👁️ Shadow AI usage monitoring

---

## How is This Different from Other "PromptSniffers"?

| Feature | This Project (Network Monitor) | Image Metadata Extractors | Prompt Analyzers |
|---------|-------------------------------|---------------------------|------------------|
| Network-level monitoring | ✅ | ❌ | ❌ |
| Real-time traffic interception | ✅ | ❌ | ❌ |
| Multi-LLM support | ✅ (7+ services) | N/A | Limited |
| DLP/Security focus | ✅ | ❌ | ❌ |
| Works on any device | ✅ | ❌ | ❌ |
| Agent installation required | ❌ (Proxy only) | N/A | N/A |

**Note**: If you're looking to extract prompts from AI-generated images, check out [Mohsyn/PromptSniffer](https://github.com/Mohsyn/PromptSniffer). This project is for network security monitoring and data loss prevention.

---

PromptSniffer is a security auditing tool designed for authorized penetration testing and corporate DLP monitoring. It captures and monitors prompts sent to Large Language Models (ChatGPT, Claude, Gemini, etc.) across your entire network, providing real-time email alerts and comprehensive logging.

---

## 🚨 Legal Notice

**AUTHORIZED USE ONLY**

This tool is designed exclusively for:
- ✅ Authorized security audits and penetration testing engagements
- ✅ Corporate DLP monitoring with proper authorization and user notification
- ✅ Security research in controlled, authorized environments
- ✅ Educational purposes with explicit consent

**Unauthorized interception of communications is illegal in most jurisdictions.**

By using this tool, you agree to:
- Obtain explicit written authorization before deployment
- Comply with all applicable laws (GDPR, CCPA, ECPA, etc.)
- Notify users of monitoring where legally required
- Use responsibly and ethically

The authors assume no liability for misuse of this tool.

---

## 🎯 Features

### Core Functionality
- 🌐 **Network-Wide Monitoring** - Captures traffic from all devices on the network
- 🤖 **Multi-LLM Support** - Monitors ChatGPT, Claude, Gemini, Copilot, Mistral, Cohere, Perplexity
- 🔒 **HTTPS Interception** - Transparent SSL/TLS decryption via mitmproxy
- 📧 **Real-Time Email Alerts** - Instant notifications via Gmail SMTP
- 🚩 **Sensitive Keyword Detection** - Flags passwords, API keys, credentials, secrets
- 📝 **Comprehensive Logging** - Detailed logs with timestamps and client info
- 🖥️ **Command-Line Only** - No GUI, pure headless operation

### Advanced Features
- ✅ **Browser-Agnostic** - Works with Chrome, Firefox, Edge, Safari, Brave
- ✅ **Incognito Mode Detection** - Captures traffic regardless of browser mode
- ✅ **Mobile Support** - iOS and Android devices
- ✅ **Automatic Decompression** - Handles gzip/compressed payloads
- ✅ **Multi-Format Support** - Extracts prompts from various API formats
- ✅ **Zero-Configuration Monitoring** - Continuous passive monitoring once deployed

---

## 🚀 Installation

### Prerequisites

- **Python 3.8 or higher**
- **Windows, Linux, or macOS**
- **Network access to target devices**
- **Gmail account with App Password** (for email alerts)

### Option 1: Automated Setup (Windows)

```bash
git clone https://github.com/DrPwner/PromptSniffer.git
cd PromptSniffer
python setup.py
```

### Option 2: Manual Setup

```bash
# Clone repository
git clone https://github.com/DrPwner/PromptSniffer.git
cd PromptSniffer

# Install dependencies
pip install -r requirements.txt

# Configure settings
cp config.json config.json.backup
# Edit config.json with your settings
```

### Gmail App Password Setup

1. Go to https://myaccount.google.com/apppasswords
2. Select **"Mail"** and your device/OS
3. Click **"Generate"**
4. Copy the 16-character password (no spaces)
5. Paste into `config.json` under `email.app_password`

---

## ⚡ Quick Start

### 1. Configure Email Settings

Edit `config.json`:

```json
{
    "email": {
        "sender": "your.email@gmail.com",
        "recipients": ["security@company.com"],
        "app_password": "YOUR_16_CHAR_APP_PASSWORD_HERE"
    }
}
```

### 2. Start PromptSniffer

**Windows:**
```bash
# Run as Administrator for network-wide monitoring
start.bat
```

**Linux/Mac:**
```bash
sudo python3 run.py
```

### 3. Enable Proxy on Your System (Windows Only)

**If testing on the same PC running PromptSniffer:**

Right-click `enable_proxy.bat` and **Run as Administrator**

This automatically configures Windows to route traffic through PromptSniffer (127.0.0.1:8080).

**When done monitoring:**

Right-click `disable_proxy.bat` and **Run as Administrator** to restore normal internet access.

**Alternative:** Manually configure proxy in Windows Settings → Network & Internet → Proxy

### 4. Configure Target Devices

On each remote device you want to monitor:

#### A. Set Proxy Settings

**Windows:**
- Settings → Network & Internet → Proxy
- Manual proxy setup
- Address: `<PromptSniffer_IP>`, Port: `8080`

**macOS:**
- System Preferences → Network → Advanced → Proxies
- HTTP/HTTPS Proxy: `<PromptSniffer_IP>:8080`

**iOS:**
- Settings → Wi-Fi → (i) → HTTP Proxy → Manual
- Server: `<PromptSniffer_IP>`, Port: `8080`

**Android:**
- Settings → Network → Long-press Wi-Fi → Modify → Advanced
- Proxy: Manual, Hostname: `<PromptSniffer_IP>`, Port: `8080`

#### B. Install CA Certificate (Required!)

1. With proxy configured, visit: **http://mitm.it**
2. Click your platform (Windows/Apple/Android)
3. Follow installation instructions for your OS

**Without certificate installation, HTTPS traffic cannot be decrypted!**

---

## 🔍 How It Works

### Architecture

```
[Target Devices] → [PromptSniffer Proxy] → [LLM APIs]
                           ↓
                    [Email Alerts]
                    [Log Files]
```

### Process Flow

1. **Traffic Interception**: mitmproxy acts as HTTPS proxy, intercepting all traffic
2. **SSL/TLS Decryption**: mitmproxy's CA certificate enables transparent HTTPS decryption
3. **LLM Detection**: Requests are matched against known LLM API endpoints
4. **Prompt Extraction**: JSON payloads are parsed to extract user prompts
5. **Keyword Analysis**: Prompts are scanned for sensitive keywords
6. **Alert Generation**: Email alerts are sent with full prompt details
7. **Logging**: All activity is logged to `prompt_sniffer.log`

---

## 🤖 Supported Services

| Service | Web UI | API | Mobile | Status |
|---------|--------|-----|--------|--------|
| ChatGPT (OpenAI) | ✅ | ✅ | ✅ | Fully Supported |
| Claude (Anthropic) | ✅ | ✅ | ✅ | Fully Supported |
| Google Gemini | ✅ | ✅ | ✅ | Fully Supported |
| Microsoft Copilot | ✅ | ✅ | ✅ | Fully Supported |
| Mistral AI | ⚠️ | ✅ | ⚠️ | API Only |
| Cohere | ⚠️ | ✅ | ⚠️ | API Only |
| Perplexity AI | ⚠️ | ✅ | ⚠️ | API Only |

---

## 📧 Email Alerts

Each captured prompt triggers an email containing:

```
PromptSniffer Alert
============================================================

Timestamp: 2025-11-07 14:35:22
Host: chatgpt.com
URL: https://chatgpt.com/backend-api/conversation
Method: POST
Client IP: 192.168.1.100

============================================================
PROMPT CONTENT:
============================================================

[User's prompt appears here]

============================================================

SENSITIVE KEYWORDS DETECTED: password, api key

REQUEST HEADERS:
------------------------------------------------------------
User-Agent: Mozilla/5.0...
Authorization: [REDACTED]
```

---

## 🐛 Troubleshooting

### No Traffic Being Captured

1. Verify proxy is configured on target device
2. Check firewall is not blocking port 8080
3. Test proxy: visit http://mitm.it

### Certificate Errors

1. Install mitmproxy certificate from http://mitm.it
2. Follow platform-specific trust instructions

### Prompts Not Extracted

1. Check debug logs: `prompt_sniffer.log`
2. LLM API format may have changed - file GitHub issue
3. Enable DEBUG logging in `prompt_interceptor.py`

For more issues, see [FAQ.md](FAQ.md)

---

## 🔧 Advanced Usage

### Network-Wide Deployment

See [ADVANCED.md](ADVANCED.md) for:
- Router-level transparent proxy
- DHCP auto-configuration
- ARP spoofing for MitM
- Database logging (SQLite)
- SIEM integration (Splunk, Datadog)
- Custom filtering by IP/time
- Run as Windows Service/Linux daemon

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch
3. Test thoroughly
4. Submit Pull Request with clear description

### Adding LLM Support

To add a new LLM service:

1. Add domain to `config.json` → `llm_endpoints`
2. Add extraction method in `prompt_interceptor.py`
3. Update documentation
4. Submit PR

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## ⚖️ Disclaimer

This tool is provided for **authorized security testing and DLP monitoring only**.

The authors:
- Do NOT condone unauthorized surveillance
- Are NOT responsible for misuse
- Assume NO liability for legal consequences
- Strongly recommend consulting legal counsel before deployment

**By using PromptSniffer, you agree to use it lawfully and ethically.**

---

## 📞 Support

- **GitHub Issues**: https://github.com/DrPwner/PromptSniffer/issues
- **Documentation**: `QUICK_START.md`, `ADVANCED.md`, `FAQ.md`
- **Security Issues**: Report via GitHub Security Advisories

---

## ⭐ Support This Project

If PromptSniffer helps you secure your network or conduct security research, please consider:
- ⭐ **Starring this repository** - It helps others discover the project
- 🐛 **Reporting bugs** - Help us improve
- 💡 **Suggesting features** - Share your ideas
- 🤝 **Contributing** - Pull requests welcome!

**Found this useful? Star the repo to show your support!**

[![Star History](https://img.shields.io/github/stars/DrPwner/PromptSniffer?style=social)](https://github.com/DrPwner/PromptSniffer/stargazers)
