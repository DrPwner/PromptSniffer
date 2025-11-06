# PromptSniffer - Quick Start Guide

## 🚀 3-Step Setup

### Step 1: Install (2 minutes)

```bash
python setup.py
```

### Step 2: Configure Gmail (1 minute)

1. Get App Password: https://myaccount.google.com/apppasswords
2. Edit `config.json`:
   ```json
   "app_password": "xxxx xxxx xxxx xxxx"  (paste here, remove spaces)
   ```

### Step 3: Run (instant)

```bash
python run.py
```

---

## 📱 Configure Target Devices

On each device you want to monitor:

### 1. Set Proxy

**Windows:** Settings → Network → Proxy → Manual
- Address: `<your_computer_IP>`
- Port: `8080`

**Mac:** System Preferences → Network → Advanced → Proxies
- HTTP/HTTPS Proxy: `<your_computer_IP>:8080`

**Phone:** Wi-Fi settings → Proxy → Manual
- Host: `<your_computer_IP>`
- Port: `8080`

### 2. Install Certificate

1. On target device, visit: **http://mitm.it**
2. Click your platform (Windows/Apple/Android)
3. Install the certificate

**Done!** PromptSniffer is now monitoring.

---

## ✅ Verify It's Working

1. On target device, visit ChatGPT/Claude
2. Type any prompt
3. Check your email - alert should arrive within seconds
4. Check `prompt_sniffer.log` - prompt should be logged

---

## 🛑 Stop Monitoring

Press `Ctrl+C` in the PromptSniffer terminal

---

## ⚙️ Configuration Options

Edit `config.json`:

**Add second recipient:**
```json
"recipients": ["first@gmail.com", "second@email.com"]
```

**Only alert on sensitive keywords (reduce email spam):**
```json
"capture_all_prompts": false
```

**Add custom keywords:**
```json
"sensitive_keywords": ["password", "secret", "your-company-name"]
```

---

## 🔍 What Gets Captured?

- ✅ ChatGPT (all browsers, incognito mode)
- ✅ Claude / Claude Code
- ✅ Google Gemini
- ✅ Microsoft Copilot
- ✅ Any browser (Chrome, Firefox, Edge, Safari)
- ✅ Incognito/Private mode
- ✅ Mobile devices (iOS, Android)

---

## 📧 Email Alerts Include:

- Timestamp
- Full prompt text
- Which LLM service (ChatGPT/Claude/etc)
- Client IP address
- Sensitive keywords detected (if any)

---

## 🐛 Troubleshooting

**No traffic captured?**
- Check proxy is configured on target device
- Check firewall isn't blocking port 8080
- Run as Administrator (Windows) or sudo (Mac/Linux)

**Certificate errors?**
- Visit http://mitm.it and install certificate
- On iOS: Settings → General → About → Certificate Trust Settings
- On Android: Install as "CA certificate" in Security

**No email alerts?**
- Check Gmail App Password is correct (16 chars)
- Check internet connection
- Look for errors in console output

---

## 📖 Need More Help?

See **README.md** for detailed documentation.

---

## ⚠️ Legal Notice

Use only for authorized security testing.
Obtain explicit permission before monitoring any network or device.
