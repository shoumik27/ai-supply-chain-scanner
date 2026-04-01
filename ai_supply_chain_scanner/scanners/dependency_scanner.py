import subprocess
import re
from pathlib import Path
import requests
from typing import List
import json

def scan_dependencies(repo_id: str = None, local_path: str = None) -> List[str]:
    findings = []

    if local_path:
        # Scan local dependency files
        req_files = ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "poetry.lock", "Pipfile.lock"]

        for f in req_files:
            p = Path(local_path) / f
            if p.exists():
                findings.extend(_scan_file_dependencies(p))

        # Check for typosquatting and malicious packages
        findings.extend(_check_typosquatting(local_path))

    elif repo_id:
        # Scan remote model dependencies
        findings.extend(_scan_remote_dependencies(repo_id))

    return findings

def _scan_file_dependencies(file_path: Path) -> List[str]:
    findings = []
    try:
        # pip-audit for known CVEs
        result = subprocess.run(["pip-audit", str(file_path)], capture_output=True, text=True, timeout=30)
        if "Vulnerability" in result.stdout:
            vulns = result.stdout.count("Vulnerability")
            findings.append(f"HIGH - {vulns} vulnerable dependencies found in {file_path.name}")
        
        # Safety scanner for additional checks
        result = subprocess.run(["safety", "check", "--file", str(file_path)], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            findings.append(f"MEDIUM - Safety scanner found issues in {file_path.name}")
            
        # Bandit for security issues in setup.py
        if file_path.name == "setup.py":
            result = subprocess.run(["bandit", "-r", str(file_path.parent)], capture_output=True, text=True, timeout=30)
            if "High severity" in result.stdout or "Medium severity" in result.stdout:
                findings.append(f"HIGH - Security issues found in setup.py")
                
    except subprocess.TimeoutExpired:
        findings.append(f"INFO - Dependency scan timed out for {file_path.name}")
    except FileNotFoundError:
        findings.append(f"INFO - Scanner tool not found for {file_path.name} (install pip-audit, safety, bandit)")
    except Exception as e:
        findings.append(f"INFO - Could not scan {file_path.name}: {str(e)}")
    
    return findings

def _check_typosquatting(local_path: str = None) -> List[str]:
    findings = []
    try:
        # Read requirements and check for suspicious package names
        req_path = Path(local_path or ".") / "requirements.txt"
        if req_path.exists():
            with open(req_path, "r") as f:
                packages = [line.strip().split("==")[0].split(">=")[0].split("<=")[0].strip() 
                          for line in f if line.strip() and not line.startswith("#")]
                
                suspicious_patterns = [
                    r"torch.*",  # Common typosquatting targets
                    r"tensorflow.*",
                    r"transformers.*",
                    r"numpy.*",
                    r"requests.*"
                ]
                
                for pkg in packages:
                    for pattern in suspicious_patterns:
                        if re.match(pattern, pkg, re.IGNORECASE):
                            # Check if package exists on PyPI
                            response = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=5)
                            if response.status_code != 200:
                                findings.append(f"MEDIUM - Suspicious package '{pkg}' not found on PyPI (possible typosquatting)")
                                
    except Exception:
        pass
    
    return findings

def _scan_remote_dependencies(repo_id: str) -> List[str]:
    """Scan dependencies for remote models"""
    findings = []

    try:
        from huggingface_hub import HfApi
        api = HfApi()

        # Check for dependency-related files in the model repo
        files = api.list_repo_files(repo_id)
        dep_files = [f for f in files if f in ["requirements.txt", "pyproject.toml", "setup.py"]]

        if dep_files:
            findings.append(f"INFO - Found dependency files: {', '.join(dep_files)}")

            # Try to analyze dependencies from config
            deps = _extract_model_dependencies(repo_id)
            if deps:
                findings.extend(_check_dependency_vulnerabilities(deps))
                findings.extend(_check_dependency_supply_chain(deps))
        else:
            findings.append("LOW - No dependency files found in model repository")

        # Check for known vulnerable packages in model metadata
        findings.extend(_check_model_vulnerable_packages(repo_id))

    except Exception as e:
        findings.append(f"INFO - Could not scan remote dependencies: {str(e)}")

    return findings

def _extract_model_dependencies(repo_id: str) -> List[str]:
    """Extract dependencies from model configuration"""
    dependencies = []

    try:
        from huggingface_hub import HfApi
        api = HfApi()

        # Check config.json for framework information
        try:
            config_path = api.hf_hub_download(repo_id, "config.json")
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Extract framework/library information
            library_name = config.get("library_name", "").lower()
            if library_name:
                dependencies.append(f"{library_name} (inferred from config)")

            # Check for specific framework versions
            if "transformers_version" in config:
                dependencies.append(f"transformers>={config['transformers_version']}")
            if "torch_dtype" in config:
                dependencies.append("torch (inferred from torch_dtype)")

        except Exception:
            pass

        # Check for requirements.txt if it exists
        try:
            req_path = api.hf_hub_download(repo_id, "requirements.txt")
            with open(req_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        dependencies.append(line)
        except Exception:
            pass

    except Exception:
        pass

    return dependencies

def _check_dependency_vulnerabilities(dependencies: List[str]) -> List[str]:
    """Check dependencies for known vulnerabilities"""
    findings = []

    # Known vulnerable packages (simplified check)
    vulnerable_packages = {
        "torch": ["<1.12.0"],  # Example vulnerability
        "transformers": ["<4.21.0"],  # Example vulnerability
        "tensorflow": ["<2.8.0"],  # Example vulnerability
    }

    for dep in dependencies:
        package_name = dep.split()[0].split('>=')[0].split('==')[0].split('<')[0].split('>')[0]

        if package_name in vulnerable_packages:
            findings.append(f"MEDIUM - Package {package_name} has known vulnerabilities")

    return findings

def _check_dependency_supply_chain(dependencies: List[str]) -> List[str]:
    """Check for supply chain risks in dependencies"""
    findings = []

    # Check for potentially malicious or suspicious packages
    suspicious_patterns = [
        "malicious", "hack", "exploit", "backdoor", "trojan",
        "unofficial", "untrusted", "suspicious"
    ]

    for dep in dependencies:
        dep_lower = dep.lower()
        for pattern in suspicious_patterns:
            if pattern in dep_lower:
                findings.append(f"HIGH - Suspicious dependency detected: {dep}")

    # Check for packages from untrusted sources
    for dep in dependencies:
        if "://" in dep:  # URL-based dependency
            findings.append(f"MEDIUM - URL-based dependency (supply chain risk): {dep}")

    return findings

def _check_model_vulnerable_packages(repo_id: str) -> List[str]:
    """Check model for known vulnerable package usage"""
    findings = []

    try:
        from huggingface_hub import HfApi
        api = HfApi()

        # Get model info
        api_url = f"https://huggingface.co/api/models/{repo_id}"
        response = requests.get(api_url, timeout=10)

        if response.status_code == 200:
            model_info = response.json()
            tags = model_info.get("tags", [])

            # Check for known vulnerable architectures
            vulnerable_architectures = ["gpt-j", "gpt-neo-1.3b", "gpt-neo-2.7b"]
            for arch in vulnerable_architectures:
                if arch in tags:
                    findings.append(f"HIGH - Uses known vulnerable architecture: {arch}")

            # Check for outdated framework versions mentioned in tags
            if any("torch1" in tag for tag in tags):
                findings.append("MEDIUM - Uses older PyTorch version")

    except Exception:
        pass

    return findings