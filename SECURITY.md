# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in PromptSniffer, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues through:

1. **GitHub Security Advisories** (Recommended)
   - Go to: https://github.com/DrPwner/PromptSniffer/security/advisories
   - Click "Report a vulnerability"
   - Provide detailed information

2. **Email** (Alternative)
   - Create a GitHub issue titled "Security Issue - Request for Private Contact"
   - We will provide secure communication channels

### What to Include

Please include the following information in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential security impact and severity
- **Reproduction**: Step-by-step instructions to reproduce
- **Environment**: Python version, OS, mitmproxy version
- **Proof of Concept**: Code or screenshots demonstrating the issue
- **Suggested Fix**: If you have ideas for remediation

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 7-30 days
  - Medium: 30-90 days
  - Low: Best effort basis

### Disclosure Policy

- We follow **coordinated disclosure** practices
- We will work with you to understand and address the issue
- We request that you do not publicly disclose the vulnerability until we have released a fix
- We will credit security researchers (unless you prefer to remain anonymous)

## Security Considerations for Users

### Deployment Security

PromptSniffer is a powerful security tool that intercepts network traffic. Please follow these best practices:

#### 1. Authorization & Legal Compliance
- ✅ Obtain explicit written authorization before deployment
- ✅ Comply with all applicable laws (GDPR, CCPA, ECPA, etc.)
- ✅ Notify users of monitoring where legally required
- ✅ Document your authorization scope
- ✅ Implement appropriate data retention policies

#### 2. Access Control
- 🔒 Restrict access to the server running PromptSniffer
- 🔒 Use strong passwords for email alert accounts
- 🔒 Store `config.json` with restricted permissions (chmod 600)
- 🔒 Limit network access to the proxy port (8080)
- 🔒 Run PromptSniffer on a dedicated, secured system

#### 3. Data Protection
- 📁 Log files contain sensitive captured prompts - protect them
- 📁 Encrypt log storage if possible
- 📁 Implement log rotation to prevent unlimited data accumulation
- 📁 Securely delete logs when no longer needed
- 📁 Restrict email alert recipient lists

#### 4. Certificate Security
- 🔐 Protect the mitmproxy CA private key
- 🔐 Only install the CA certificate on authorized devices
- 🔐 Revoke/regenerate certificates if compromised
- 🔐 Monitor certificate installation across devices

#### 5. Network Security
- 🌐 Deploy behind firewalls
- 🌐 Use VLANs to segment monitoring traffic
- 🌐 Monitor for unauthorized proxy usage
- 🌐 Implement rate limiting to prevent abuse
- 🌐 Log all access attempts

### Known Security Limitations

#### Certificate Trust
- Users who install the mitmproxy CA certificate are trusting ALL traffic intercepted by that proxy
- Compromised proxy = compromised traffic
- Malicious actors with access to the proxy can intercept all HTTPS traffic

#### Bypassability
- Users can bypass monitoring by:
  - Disabling proxy settings
  - Using VPNs
  - Using cellular data
  - Using certificate-pinned applications
  - Using Tor or other anonymity networks

#### Log Exposure
- `prompt_sniffer.log` contains plaintext captured prompts
- May include passwords, API keys, or other secrets
- Unauthorized access to logs = data breach

#### Email Security
- Email alerts are sent in plaintext (SMTP/TLS)
- Email accounts can be compromised
- Alerts contain sensitive prompt content

### Security Hardening Recommendations

```bash
# Restrict config file permissions
chmod 600 config.json

# Restrict log file permissions
chmod 600 prompt_sniffer.log

# Run with minimal privileges (after binding to port)
# Use capabilities on Linux instead of root
setcap 'cap_net_bind_service=+ep' /usr/bin/python3

# Firewall rules (example)
# Only allow specific IPs to use the proxy
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### Sensitive Data Handling

PromptSniffer captures and stores sensitive information. You must:

1. **Minimize Collection**
   - Only capture what's necessary for your security objectives
   - Use `capture_all_prompts: false` to reduce data collection

2. **Secure Storage**
   - Encrypt storage volumes
   - Use secure file permissions
   - Implement access controls

3. **Retention Limits**
   - Define data retention policies
   - Automatically purge old logs
   - Document retention periods

4. **Incident Response**
   - Have a plan for data breaches
   - Know who to notify
   - Document breach response procedures

## Third-Party Dependencies

PromptSniffer relies on:

- **mitmproxy**: HTTPS interception proxy
  - Security advisories: https://github.com/mitmproxy/mitmproxy/security
- **Python standard library**: smtplib, logging, json
  - Follow Python security updates

We monitor security advisories for all dependencies and will update as needed.

## Security Updates

Security updates will be:
- Released as patches to the latest version
- Announced via GitHub Security Advisories
- Documented in release notes
- Tagged with `[SECURITY]` prefix

## Compliance Considerations

### GDPR (EU)
- Prompts may contain personal data
- Users must be notified of monitoring
- Implement data subject access rights
- Document legal basis for processing

### CCPA (California)
- Notify users of data collection
- Honor opt-out requests
- Implement data deletion procedures

### HIPAA (Healthcare)
- Do not use for PHI without proper safeguards
- Implement Business Associate Agreements
- Ensure encryption and access controls

### Corporate Policies
- Align with corporate acceptable use policies
- Document authorization and scope
- Train administrators on responsible use

## Bug Bounty

We currently do not have a formal bug bounty program, but we deeply appreciate security research contributions. Researchers who report valid vulnerabilities will be:

- Credited in release notes (if desired)
- Listed in our security acknowledgments
- Provided with early notification of fixes

## Security Best Practices for Contributors

If you're contributing code:

- ✅ Never commit secrets, API keys, or credentials
- ✅ Review code for injection vulnerabilities
- ✅ Validate and sanitize all user inputs
- ✅ Use parameterized queries (if adding database support)
- ✅ Follow principle of least privilege
- ✅ Document security implications of new features

## Questions?

For non-sensitive security questions, please open a regular GitHub issue.

For security vulnerabilities, please use the private reporting methods described above.

---

**Remember**: PromptSniffer is a powerful security tool. With great power comes great responsibility. Use it ethically and legally.
