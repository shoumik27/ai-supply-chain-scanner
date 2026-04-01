import re
import os
from pathlib import Path
from typing import List
import requests

def scan_access_control(repo_id: str = None, local_path: str = None) -> List[str]:
    findings = []
    
    if local_path:
        findings.extend(_scan_local_access_control(local_path))
    if repo_id:
        findings.extend(_scan_remote_access_control(repo_id))
    
    return findings

def _scan_local_access_control(local_path: str) -> List[str]:
    findings = []
    path = Path(local_path)
    
    # Check for leaked tokens/API keys
    token_patterns = [
        r"sk-[a-zA-Z0-9]{48}",  # OpenAI
        r"hf_[a-zA-Z0-9]{34}",  # HuggingFace
        r"AKIA[0-9A-Z]{16}",   # AWS
        r"AIza[0-9A-Za-z-_]{35}",  # Google
    ]
    
    for file_path in path.rglob("*"):
        if file_path.is_file() and not file_path.name.startswith('.'):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                    for pattern in token_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            findings.append(f"CRITICAL - Potential leaked API token found in {file_path.name}")
                            
            except Exception:
                continue
    
    # Check for insecure configurations
    config_files = ["config.json", "tokenizer_config.json", ".env", "secrets.json"]
    for config in config_files:
        config_path = path / config
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                    if '"trust_remote_code": true' in content:
                        findings.append(f"HIGH - trust_remote_code enabled in {config}")
                    
                    if '"private": false' in content or '"public": true' in content:
                        findings.append(f"MEDIUM - Model configuration allows public access")
                        
            except Exception:
                continue
    
    # Check file permissions (on Unix-like systems)
    try:
        for file_path in path.rglob("*.json"):
            if os.name != 'nt':  # Not Windows
                stat = file_path.stat()
                if stat.st_mode & 0o077:  # World readable/writable
                    findings.append(f"MEDIUM - Insecure permissions on {file_path.name}")
    except Exception:
        pass
    
    return findings

def _scan_remote_access_control(repo_id: str) -> List[str]:
    findings = []
    try:
        # Check repository visibility and permissions
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            model_info = response.json()

            # Basic visibility check
            if model_info.get("private", False):
                findings.append("INFO - Model is private (good for access control)")
            else:
                findings.append("LOW - Model is publicly accessible")

            # Check download statistics (popularity = higher risk)
            downloads = model_info.get("downloads", 0)
            if downloads > 1000000:  # 1M+ downloads
                findings.append("MEDIUM - High download volume increases supply chain risk")
            elif downloads > 100000:  # 100K+ downloads
                findings.append("LOW - Moderate download volume")

            # Check for security-related tags
            tags = model_info.get("tags", [])
            security_tags = ["gated", "safe", "verified", "enterprise"]
            has_security_tags = any(tag in tags for tag in security_tags)

            if not has_security_tags:
                findings.append("MEDIUM - Model lacks gated access controls or security tags")

            # Check contributor diversity and count
            author_info = model_info.get("author", {})
            if isinstance(author_info, dict):
                num_models = author_info.get("models", 0)
                if num_models < 3:
                    findings.append("LOW - Publisher has limited model portfolio")

            # Check for enterprise features
            has_enterprise = _check_enterprise_features(model_info)
            if not has_enterprise:
                findings.append("LOW - Model lacks enterprise security features")

            # Check model card for exposed information
            if "cardData" in model_info:
                card_content = str(model_info["cardData"]).lower()
                if "http://" in card_content or "https://" in card_content:
                    if any(word in card_content for word in ["api", "endpoint", "webhook", "token"]):
                        findings.append("MEDIUM - Model card contains API endpoints or tokens")

        # Additional security checks
        additional_findings = _check_model_security_metadata(repo_id)
        findings.extend(additional_findings)

    except Exception as e:
        findings.append(f"INFO - Could not check remote access control: {str(e)}")

    return findings

def _check_enterprise_features(model_info: dict) -> bool:
    """Check if model has enterprise-grade security features"""
    tags = model_info.get("tags", [])

    enterprise_indicators = [
        "enterprise", "gated", "safe", "verified", "audited",
        "compliance", "soc2", "iso27001", "gdpr"
    ]

    return any(tag in tags for tag in enterprise_indicators)

def _check_model_security_metadata(repo_id: str) -> List[str]:
    """Additional security metadata checks"""
    findings = []

    try:
        # Check for license information
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            model_info = response.json()

            # Check license
            license_info = model_info.get("license")
            if not license_info:
                findings.append("LOW - No license specified")
            elif license_info.lower() in ["other", "unknown"]:
                findings.append("MEDIUM - License type unclear")

            # Check for library usage that might indicate security
            library_name = model_info.get("library_name")
            if library_name == "transformers":
                findings.append("INFO - Uses HuggingFace Transformers (generally secure)")
            elif library_name not in ["transformers", "diffusers", "sentence-transformers"]:
                findings.append(f"LOW - Uses less common library: {library_name}")

    except Exception:
        pass

    return findings