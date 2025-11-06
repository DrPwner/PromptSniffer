"""
PromptSniffer - LLM Prompt Network Interceptor
Monitors network traffic for ChatGPT, Claude, and other LLM prompts
"""

import json
import logging
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

from mitmproxy import http, ctx


class PromptInterceptor:
    """Intercepts and monitors LLM API traffic"""

    def __init__(self):
        self.config = self._load_config()
        self.logger = self._setup_logging()
        self.llm_domains = self._flatten_llm_domains()
        self.logger.info("PromptSniffer initialized successfully")
        self.logger.info(f"Monitoring {len(self.llm_domains)} LLM domains")

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config.json"""
        config_path = Path(__file__).parent / "config.json"
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"ERROR: config.json not found at {config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in config.json: {e}")
            sys.exit(1)

    def _setup_logging(self) -> logging.Logger:
        """Setup logging to file"""
        log_file = self.config['monitoring']['log_file']

        # Create logger
        logger = logging.getLogger('PromptSniffer')
        logger.setLevel(logging.DEBUG)  # Enable DEBUG logging

        # File handler
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)  # Enable DEBUG in file

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # Also log to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        return logger

    def _flatten_llm_domains(self) -> List[str]:
        """Flatten all LLM domains from config into a single list"""
        domains = []
        for provider, domain_list in self.config['llm_endpoints'].items():
            domains.extend(domain_list)
        return domains

    def _is_llm_request(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is to an LLM endpoint"""
        host = flow.request.pretty_host
        return any(domain in host for domain in self.llm_domains)

    def _extract_openai_prompt(self, content: bytes) -> Optional[str]:
        """Extract prompt from OpenAI/ChatGPT API request"""
        try:
            # Try to decode and parse JSON
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                # Content might be gzip compressed
                import gzip
                try:
                    content_str = gzip.decompress(content).decode('utf-8')
                except Exception:
                    self.logger.debug("Could not decompress content")
                    return None

            data = json.loads(content_str)

            # Debug: Log the keys in the request
            self.logger.debug(f"OpenAI request keys: {list(data.keys())}")

            # ChatGPT Web UI format (new)
            if 'messages' in data:
                messages = data['messages']
                if isinstance(messages, list) and len(messages) > 0:
                    # Get the last user message
                    for msg in reversed(messages):
                        if isinstance(msg, dict):
                            if msg.get('role') == 'user':
                                content_field = msg.get('content', '')
                                # Content might be a dict with 'parts'
                                if isinstance(content_field, dict):
                                    if 'parts' in content_field:
                                        parts = content_field['parts']
                                        if isinstance(parts, list) and len(parts) > 0:
                                            return parts[0]
                                elif isinstance(content_field, str):
                                    return content_field
                        elif isinstance(msg, str):
                            # Sometimes messages are just strings
                            return msg

            # API format
            if 'prompt' in data:
                return data['prompt']

            # Check for 'action' field (ChatGPT web format)
            if 'action' in data and data['action'] == 'next':
                if 'messages' in data:
                    messages = data['messages']
                    if isinstance(messages, list) and len(messages) > 0:
                        last_msg = messages[-1]
                        if isinstance(last_msg, dict):
                            if 'content' in last_msg:
                                content_field = last_msg['content']
                                if isinstance(content_field, dict) and 'parts' in content_field:
                                    return ' '.join(str(p) for p in content_field['parts'])
                                return str(content_field)

        except json.JSONDecodeError as e:
            self.logger.debug(f"Not JSON content: {e}")
        except Exception as e:
            self.logger.error(f"Error extracting OpenAI prompt: {e}")

        return None

    def _extract_anthropic_prompt(self, content: bytes) -> Optional[str]:
        """Extract prompt from Anthropic/Claude API request"""
        try:
            data = json.loads(content)

            # Claude API format
            if 'messages' in data:
                messages = data['messages']
                if isinstance(messages, list) and len(messages) > 0:
                    for msg in reversed(messages):
                        if msg.get('role') == 'user':
                            content = msg.get('content', '')
                            if isinstance(content, str):
                                return content
                            elif isinstance(content, list):
                                # Handle multipart content
                                text_parts = [c.get('text', '') for c in content if c.get('type') == 'text']
                                return ' '.join(text_parts)

            # Legacy format
            if 'prompt' in data:
                return data['prompt']

        except Exception as e:
            self.logger.error(f"Error extracting Anthropic prompt: {e}")

        return None

    def _extract_google_prompt(self, content: bytes) -> Optional[str]:
        """Extract prompt from Google Gemini API request"""
        try:
            data = json.loads(content)

            # Gemini API format
            if 'contents' in data:
                contents = data['contents']
                if isinstance(contents, list) and len(contents) > 0:
                    for item in reversed(contents):
                        if item.get('role') == 'user':
                            parts = item.get('parts', [])
                            if parts and 'text' in parts[0]:
                                return parts[0]['text']

            # Legacy format
            if 'prompt' in data:
                return data['prompt']

        except Exception as e:
            self.logger.error(f"Error extracting Google prompt: {e}")

        return None

    def _extract_generic_prompt(self, content: bytes) -> Optional[str]:
        """Try to extract prompt from generic API request"""
        try:
            data = json.loads(content)

            # Common patterns
            for key in ['prompt', 'query', 'question', 'input', 'text', 'message']:
                if key in data:
                    return str(data[key])

            # Check for messages array
            if 'messages' in data:
                messages = data['messages']
                if isinstance(messages, list) and len(messages) > 0:
                    last_msg = messages[-1]
                    if isinstance(last_msg, dict):
                        return last_msg.get('content') or last_msg.get('text')

        except Exception as e:
            self.logger.error(f"Error extracting generic prompt: {e}")

        return None

    def _extract_prompt(self, flow: http.HTTPFlow) -> Optional[str]:
        """Extract prompt from request based on the provider"""
        if not flow.request.content:
            return None

        host = flow.request.pretty_host
        content = flow.request.content

        # Try provider-specific extraction
        if any(d in host for d in self.config['llm_endpoints']['openai']):
            prompt = self._extract_openai_prompt(content)
        elif any(d in host for d in self.config['llm_endpoints']['anthropic']):
            prompt = self._extract_anthropic_prompt(content)
        elif any(d in host for d in self.config['llm_endpoints']['google']):
            prompt = self._extract_google_prompt(content)
        else:
            prompt = self._extract_generic_prompt(content)

        return prompt

    def _check_sensitive_content(self, prompt: str) -> List[str]:
        """Check if prompt contains sensitive keywords"""
        if not self.config['monitoring']['alert_on_sensitive_keywords']:
            return []

        keywords = self.config['monitoring']['sensitive_keywords']
        found = []

        prompt_lower = prompt.lower()
        for keyword in keywords:
            if keyword.lower() in prompt_lower:
                found.append(keyword)

        return found

    def _send_email_alert(self, prompt: str, flow: http.HTTPFlow, sensitive_keywords: List[str]):
        """Send email alert for detected prompt"""
        try:
            email_config = self.config['email']

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[PromptSniffer] LLM Prompt Detected - {flow.request.pretty_host}"
            msg['From'] = email_config['sender']
            msg['To'] = ', '.join(email_config['recipients'])

            # Build email body
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            body = f"""
PromptSniffer Alert
{'='*60}

Timestamp: {timestamp}
Host: {flow.request.pretty_host}
URL: {flow.request.pretty_url}
Method: {flow.request.method}
Client IP: {flow.client_conn.peername[0] if flow.client_conn.peername else 'Unknown'}

{'='*60}
PROMPT CONTENT:
{'='*60}

{prompt}

{'='*60}
"""

            if sensitive_keywords:
                body += f"\n\nSENSITIVE KEYWORDS DETECTED: {', '.join(sensitive_keywords)}\n"

            # Request headers
            body += "\n\nREQUEST HEADERS:\n"
            body += "-" * 60 + "\n"
            for name, value in flow.request.headers.items():
                # Mask authorization headers
                if 'auth' in name.lower() or 'token' in name.lower():
                    body += f"{name}: [REDACTED]\n"
                else:
                    body += f"{name}: {value}\n"

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                server.login(email_config['sender'], email_config['app_password'])
                server.send_message(msg)

            self.logger.info(f"Email alert sent to {len(email_config['recipients'])} recipient(s)")

        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each request"""
        try:
            # Check if this is an LLM request
            if not self._is_llm_request(flow):
                return

            # Only process POST requests (API calls)
            if flow.request.method != "POST":
                return

            self.logger.info(f"LLM request detected: {flow.request.pretty_host} - {flow.request.path}")

            # Debug: Log first 500 chars of request content for conversation endpoint
            if '/conversation' in flow.request.path and flow.request.content:
                try:
                    content_preview = flow.request.content[:500].decode('utf-8', errors='replace')
                    self.logger.debug(f"Request content preview: {content_preview}")
                except Exception as e:
                    self.logger.debug(f"Could not preview content: {e}")

            # Extract prompt
            prompt = self._extract_prompt(flow)

            if not prompt:
                self.logger.warning(f"Could not extract prompt from {flow.request.pretty_host}")
                return

            self.logger.info(f"Prompt extracted ({len(prompt)} chars)")

            # Check for sensitive content
            sensitive_keywords = self._check_sensitive_content(prompt)

            if sensitive_keywords:
                self.logger.warning(f"SENSITIVE KEYWORDS DETECTED: {', '.join(sensitive_keywords)}")

            # Log the prompt
            self.logger.info(f"PROMPT: {prompt[:200]}..." if len(prompt) > 200 else f"PROMPT: {prompt}")

            # Send email alert
            if self.config['monitoring']['capture_all_prompts'] or sensitive_keywords:
                self._send_email_alert(prompt, flow, sensitive_keywords)

        except Exception as e:
            self.logger.error(f"Error processing request: {e}", exc_info=True)


# mitmproxy addon
addons = [PromptInterceptor()]
