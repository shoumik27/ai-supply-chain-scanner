from typing import List, Dict
import json
from pathlib import Path

import json
from pathlib import Path
from typing import List, Dict
import requests
from datetime import datetime, timedelta

class SecurityPolicy:
    def __init__(self, config_path: str = None):
        self.policies = {
            "require_signature": True,
            "require_hash": True,
            "block_unsigned_models": True,
            "block_unknown_publishers": True,
            "block_remote_code": True,
            "allowed_publishers": ["microsoft", "google", "meta", "huggingface", "openai"],
            "max_model_size": 10 * 1024 * 1024 * 1024,  # 10GB
            "require_slsa": False,  # Experimental
            "min_publisher_reputation": 0.5,  # Minimum reputation score
            "max_model_age_days": 365,  # Flag models older than 1 year
        }

        if config_path and Path(config_path).exists():
            with open(config_path, "r") as f:
                user_policies = json.load(f)
                self.policies.update(user_policies)

def check_policies(repo_id: str, local_path: str = None, policy_config: str = None) -> List[str]:
    findings = []
    policy = SecurityPolicy(policy_config)
    
    if local_path:
        findings.extend(_check_local_policies(local_path, policy))
    else:
        findings.extend(_check_remote_policies(repo_id, policy))
    
    return findings

def _check_local_policies(local_path: str, policy: SecurityPolicy) -> List[str]:
    findings = []
    path = Path(local_path)
    
    # Check for required files
    if policy.policies["require_hash"]:
        hash_files = list(path.glob("*.sha256"))
        if not hash_files:
            findings.append("HIGH - Policy violation: Missing integrity hash files")
    
    if policy.policies["require_signature"]:
        sig_files = list(path.glob("*.sig"))
        if not sig_files:
            findings.append("HIGH - Policy violation: Missing digital signatures")
    
    # Check model size
    total_size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    if total_size > policy.policies["max_model_size"]:
        findings.append(f"MEDIUM - Policy violation: Model size {total_size} exceeds limit")
    
    # Check for remote code usage
    config_files = ["config.json", "model_config.json"]
    for config in config_files:
        config_path = path / config
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config_data = json.load(f)
                    if config_data.get("trust_remote_code", False) and policy.policies["block_remote_code"]:
                        findings.append("CRITICAL - Policy violation: trust_remote_code enabled")
            except Exception:
                continue
    
    return findings

def _check_remote_policies(repo_id: str, policy: SecurityPolicy) -> List[str]:
    findings = []

    # Extract publisher
    publisher = repo_id.split("/")[0] if "/" in repo_id else "unknown"

    # Check publisher reputation
    reputation_score = _get_publisher_reputation(publisher)
    if reputation_score < policy.policies["min_publisher_reputation"]:
        findings.append(f"MEDIUM - Publisher '{publisher}' has low reputation score ({reputation_score:.2f})")

    # Check if publisher is in allowed list
    if policy.policies["block_unknown_publishers"] and publisher not in policy.policies["allowed_publishers"]:
        findings.append(f"MEDIUM - Policy violation: Unknown publisher '{publisher}'")

    # Model-specific signature checking
    signature_status = _check_model_signature(repo_id)
    if policy.policies["require_signature"] and not signature_status["verified"]:
        severity = "HIGH" if signature_status["method"] == "none" else "MEDIUM"
        findings.append(f"{severity} - Model signature: {signature_status['message']}")

    # Check model age and update frequency
    model_age_days = _get_model_age_days(repo_id)
    if model_age_days > policy.policies["max_model_age_days"]:
        findings.append(f"LOW - Model is {model_age_days} days old, consider updating")

    # Check for known security issues
    security_issues = _check_known_vulnerabilities(repo_id)
    findings.extend(security_issues)

    return findings

def should_block_loading(repo_id: str, local_path: str = None, policy_config: str = None) -> bool:
    """Returns True if model should be blocked from loading based on policies"""
    violations = check_policies(repo_id, local_path, policy_config)
    critical_violations = [v for v in violations if "CRITICAL" in v]
    return len(critical_violations) > 0

def _get_publisher_reputation(publisher: str) -> float:
    """Get reputation score for a publisher (0.0 to 1.0)"""
    # Known reputable publishers
    reputable_publishers = {
        "microsoft": 0.95,
        "google": 0.95,
        "meta": 0.90,
        "huggingface": 0.90,
        "openai": 0.85,
        "anthropic": 0.85,
        "stabilityai": 0.80,
        "bigscience": 0.75,
        "facebook": 0.70,
        "eleutherai": 0.70,
    }

    # Return known reputation or default low score
    return reputable_publishers.get(publisher.lower(), 0.3)

def _check_model_signature(repo_id: str) -> Dict[str, any]:
    """Check if model has verifiable signatures"""
    try:
        # Check for signature files in repo
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            model_info = response.json()

            # Check for signature-related files
            files = model_info.get("siblings", [])
            file_names = [f["rfilename"] for f in files]

            has_sig_files = any(f.endswith(('.sig', '.asc', '.pem')) for f in file_names)
            has_checksum = any(f.endswith(('.sha256', '.md5')) for f in file_names)

            if has_sig_files:
                return {"verified": True, "method": "signature_file", "message": "Digital signature files found"}
            elif has_checksum:
                return {"verified": True, "method": "checksum", "message": "Checksum files found"}
            else:
                return {"verified": False, "method": "none", "message": "No signature or checksum files found"}

    except Exception as e:
        return {"verified": False, "method": "error", "message": f"Could not check signatures: {str(e)}"}

    return {"verified": False, "method": "none", "message": "Signature check failed"}

def _get_model_age_days(repo_id: str) -> int:
    """Get model age in days since last update"""
    try:
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            model_info = response.json()
            last_modified = model_info.get("lastModified")

            if last_modified:
                # Parse ISO date
                last_modified_date = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
                age = datetime.now(last_modified_date.tzinfo) - last_modified_date
                return age.days

    except Exception:
        pass

    return 0  # Unknown age

def _check_known_vulnerabilities(repo_id: str) -> List[str]:
    """Check for known vulnerabilities in the model"""
    findings = []

    try:
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            model_info = response.json()
            tags = model_info.get("tags", [])

            # Check for problematic tags
            if "unrestricted" in tags or "uncensored" in tags:
                findings.append("HIGH - Model tagged as unrestricted/uncensored")

            # Check for known vulnerable architectures
            if any(tag in ["gpt-j", "gpt-neo"] for tag in tags):
                findings.append("MEDIUM - Architecture has known vulnerabilities")

    except Exception:
        pass

    return findings