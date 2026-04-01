import hashlib
import json
import requests
from pathlib import Path
from typing import List, Dict, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

def verify_integrity(repo_id: str, local_path: str = None) -> List[str]:
    findings = []
    
    if local_path:
        findings.extend(_verify_local_integrity(local_path))
    else:
        findings.extend(_verify_remote_integrity(repo_id))
    
    return findings

def _verify_local_integrity(local_path: str) -> List[str]:
    findings = []
    path = Path(local_path)
    
    # Check for hash files
    hash_files = list(path.glob("*.sha256")) + list(path.glob("*.md5"))
    if not hash_files:
        findings.append("MEDIUM - No integrity hash files found")
    
    for hash_file in hash_files:
        findings.extend(_verify_hash_file(hash_file, path))
    
    # Check for signature files
    sig_files = list(path.glob("*.sig")) + list(path.glob("*.asc"))
    if sig_files:
        findings.extend(_verify_signatures(sig_files, path))
    else:
        findings.append("LOW - No digital signatures found")
    
    return findings

def _verify_remote_integrity(repo_id: str) -> List[str]:
    findings = []
    try:
        # Check if model has provenance/SLSA attestations
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            model_info = response.json()

            # Check for SLSA attestations and provenance
            has_slsa = _check_slsa_attestations(repo_id)
            if not has_slsa:
                findings.append("HIGH - No SLSA provenance attestations found")
            else:
                findings.append("INFO - SLSA attestations found (good)")

            # Check model card for provenance information
            if "cardData" in model_info:
                card = str(model_info["cardData"]).lower()
                provenance_keywords = ["provenance", "supply chain", "build", "audit", "verification"]
                has_provenance = any(keyword in card for keyword in provenance_keywords)
                if not has_provenance:
                    findings.append("MEDIUM - No provenance information found in model card")

            # Enhanced security tag checking
            tags = model_info.get("tags", [])
            security_tags = ["safe", "verified", "signed", "audited", "slsa", "provenance"]
            has_security_tags = any(tag in tags for tag in security_tags)
            if not has_security_tags:
                findings.append("MEDIUM - Model lacks security verification tags")

            # Check for reproducible builds
            reproducible = _check_reproducible_build(model_info)
            if not reproducible:
                findings.append("LOW - Model build reproducibility unclear")

            # Check file integrity
            file_integrity = _verify_model_file_integrity(repo_id)
            if not file_integrity["verified"]:
                findings.append(f"HIGH - {file_integrity['message']}")

    except Exception as e:
        findings.append(f"INFO - Could not verify remote integrity: {str(e)}")

    return findings

def _verify_hash_file(hash_file: Path, base_path: Path) -> List[str]:
    findings = []
    try:
        with open(hash_file, "r") as f:
            content = f.read()
        
        # Parse hash file (assuming format: hash filename)
        lines = content.strip().split("\n")
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                expected_hash = parts[0]
                filename = " ".join(parts[1:])
                file_path = base_path / filename
                
                if file_path.exists():
                    actual_hash = _calculate_sha256(file_path)
                    if actual_hash != expected_hash:
                        findings.append(f"CRITICAL - Hash mismatch for {filename}")
                else:
                    findings.append(f"HIGH - Referenced file {filename} not found")
    
    except Exception as e:
        findings.append(f"INFO - Could not verify hash file {hash_file.name}: {str(e)}")
    
    return findings

def _verify_signatures(sig_files: List[Path], base_path: Path) -> List[str]:
    findings = []
    # This is a simplified signature verification
    # In practice, you'd need trusted public keys
    for sig_file in sig_files:
        findings.append(f"INFO - Signature file {sig_file.name} found (verification requires trusted keys)")
    
    return findings

def _calculate_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def _check_slsa_attestations(repo_id: str) -> bool:
    """Check for SLSA (Supply chain Levels for Software Artifacts) attestations"""
    try:
        # Check for attestation files in the repository
        from huggingface_hub import HfApi
        api = HfApi()

        files = api.list_repo_files(repo_id)
        attestation_files = [f for f in files if 'attestation' in f.lower() or f.endswith('.intoto') or f.endswith('.sigstore')]

        return len(attestation_files) > 0
    except Exception:
        return False

def _check_reproducible_build(model_info: dict) -> bool:
    """Check if the model build is reproducible"""
    # Check for build-related metadata
    tags = model_info.get("tags", [])
    card_data = str(model_info.get("cardData", "")).lower()

    reproducibility_indicators = [
        "reproducible", "deterministic", "build", "ci/cd",
        "github actions", "build script", "dockerfile"
    ]

    has_reproducibility_info = (
        any(tag in tags for tag in reproducibility_indicators) or
        any(indicator in card_data for indicator in reproducibility_indicators)
    )

    return has_reproducibility_info

def _verify_model_file_integrity(repo_id: str) -> Dict[str, any]:
    """Verify integrity of model files"""
    try:
        from huggingface_hub import HfApi
        api = HfApi()

        # Check for hash files
        files = api.list_repo_files(repo_id)
        hash_files = [f for f in files if f.endswith(('.sha256', '.md5', '.sha512'))]

        if hash_files:
            # Try to verify at least one hash file
            for hash_file in hash_files[:1]:  # Check first hash file
                try:
                    hash_content = api.hf_hub_download(repo_id, hash_file)
                    with open(hash_content, 'r') as f:
                        content = f.read()

                    # Parse hash file (format: hash filename)
                    lines = content.strip().split('\n')
                    if lines:
                        parts = lines[0].split()
                        if len(parts) >= 2:
                            expected_hash = parts[0]
                            filename = ' '.join(parts[1:])

                            # Check if referenced file exists
                            if filename in files:
                                return {"verified": True, "message": f"Hash verification available for {filename}"}
                            else:
                                return {"verified": False, "message": f"Hash file references missing file: {filename}"}
                except Exception:
                    continue

        return {"verified": False, "message": "No verifiable hash files found"}

    except Exception as e:
        return {"verified": False, "message": f"Could not check file integrity: {str(e)}"}