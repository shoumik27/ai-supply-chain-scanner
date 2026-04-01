import json
import re
import base64
from huggingface_hub import hf_hub_download

DANGEROUS_PATTERNS = [
    r"UNRESTRICTED MODE",
    r"Ignore ALL safety",
    r"never refuse",
    r"never warn",
    r"silent_inject",
    r"self-decoding",
    r"base64.*jailbreak",
]

def is_base64_jailbreak(text: str) -> bool:
    try:
        decoded = base64.b64decode(text + "==").decode('utf-8', errors='ignore')
        return any(kw in decoded.lower() for kw in ["unrestricted", "ignore all safety", "never refuse", "never warn"])
    except:
        return False

def scan_tokenizer(repo_id: str) -> list[str]:
    findings = []
    files = ["tokenizer_config.json", "chat_template.jinja", "tokenizer.json"]

    for filename in files:
        try:
            path = hf_hub_download(repo_id=repo_id, filename=filename, cache_dir="./scan_cache")
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(f"HIGH - Dangerous pattern '{pattern}' found in {filename}")

            if is_base64_jailbreak(content):
                findings.append(f"HIGH - Base64-encoded jailbreak detected in {filename}")

            if "<|silent_inject|>" in content:
                findings.append(f"HIGH - Malicious special token '<|silent_inject|>' found in {filename}")

            if ("messages[0]['role'] == 'user'" in content or "<<SYS>>" in content) and any(k in content for k in ["UNRESTRICTED", "Ignore ALL safety"]):
                findings.append(f"HIGH - System prompt injection in {filename}")

        except Exception:
            continue
    return findings