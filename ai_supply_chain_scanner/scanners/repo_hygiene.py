from huggingface_hub import HfApi
import json

def scan_repo_hygiene(repo_id: str) -> list[str]:
    findings = []
    api = HfApi()
    try:
        files = api.list_repo_files(repo_id)

        # Check for suspicious file types (expanded list)
        suspicious_extensions = ('.sh', '.exe', '.pkl', 'setup.py', '.py', '.js', '.bat', '.cmd')
        suspicious_files = [f for f in files if any(f.endswith(ext) for ext in suspicious_extensions)]

        # Exclude known safe files
        safe_files = {'__init__.py', 'setup.py'}  # setup.py might be legitimate
        suspicious_files = [f for f in suspicious_files if f not in safe_files]

        if suspicious_files:
            findings.append(f"MEDIUM - Suspicious file types found: {', '.join(suspicious_files[:5])}")

        # Check for trust_remote_code in filenames
        if any("trust_remote_code" in f.lower() for f in files):
            findings.append("HIGH - trust_remote_code mentioned in repo files")

        # Check README for security warnings
        if "README.md" in files:
            try:
                readme = api.hf_hub_download(repo_id, "README.md")
                with open(readme, 'r', encoding='utf-8', errors='ignore') as f:
                    readme_content = f.read().lower()

                if "trust_remote_code=true" in readme_content:
                    findings.append("HIGH - README mentions trust_remote_code=True")
                if "unsafe" in readme_content and "load" in readme_content:
                    findings.append("MEDIUM - README mentions unsafe loading")
            except:
                pass

        # Check config.json for security issues
        if "config.json" in files:
            try:
                config_path = api.hf_hub_download(repo_id, "config.json")
                with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                    config = json.load(f)

                # Check for custom auto_map (requires custom code)
                if config.get("auto_map"):
                    findings.append("MEDIUM - Model uses custom auto_map (requires loading custom code)")

                # Check for trust_remote_code
                if config.get("trust_remote_code", False):
                    findings.append("CRITICAL - trust_remote_code is enabled in config")

                # Check for transformers_version compatibility
                if "transformers_version" not in config:
                    findings.append("LOW - No transformers version specified in config")

            except:
                findings.append("INFO - Could not analyze config.json")

        # Check for model card metadata
        if "README.md" in files:
            findings.append("LOW - No provenance information found in model card")
        else:
            findings.append("MEDIUM - Missing model card (README.md)")

        # Check for security verification tags
        security_indicators = ["security", "verified", "audited", "slsa", "sigstore"]
        has_security_info = any(any(indicator in f.lower() for indicator in security_indicators) for f in files)
        if not has_security_info:
            findings.append("MEDIUM - Model lacks security verification tags")

    except Exception as e:
        findings.append(f"INFO - Could not scan repo hygiene: {str(e)}")

    return findings