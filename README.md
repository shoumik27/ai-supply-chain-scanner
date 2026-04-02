# AI Supply Chain Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/ai-supply-chain-scanner.svg)](https://pypi.org/project/ai-supply-chain-scanner/)

A comprehensive, enterprise-grade CLI tool for detecting supply-chain vulnerabilities in AI/ML models. Designed for security teams, MLOps engineers, and red-teamers who need to validate the security of AI models before deployment.

## 🎯 What It Does

The AI Supply Chain Vulnerability Scanner performs automated security analysis across the entire AI model lifecycle, from training data to deployment. It identifies vulnerabilities that could compromise model integrity, leak sensitive information, or enable malicious behavior.

### Key Capabilities

- **🔍 Multi-Layer Security Analysis**: Scans models across 12+ security dimensions
- **📊 Risk-Based Assessment**: Provides actionable risk scores (Critical/High/Medium/Low)
- **🔄 Continuous Monitoring**: Automated drift detection and alerting
- **🏢 Enterprise Ready**: Policy enforcement, compliance checking, and audit trails
- **🔧 Extensible Architecture**: Plugin-based scanner system for custom checks

## 🏗️ How It Works

The scanner operates through a modular architecture that examines different attack surfaces:

### 1. **Static Analysis**
- Downloads model files from HuggingFace Hub
- Analyzes configuration files, tokenizers, and model artifacts
- Performs pattern matching for known vulnerabilities

### 2. **Dynamic Analysis**
- Loads models in safe environments for behavioral testing
- Executes trigger-based prompts to detect backdoors
- Compares outputs against baseline safe models

### 3. **Dependency Analysis**
- Scans Python package dependencies for known CVEs
- Detects typosquatting and malicious package attacks
- Validates software bill of materials (SBOM)

### 4. **Policy Enforcement**
- Applies configurable security policies
- Blocks models that violate organizational standards
- Generates compliance reports

### 5. **Continuous Monitoring**
- Tracks model versions and detects changes
- Alerts on security drift or new vulnerabilities
- Maintains audit logs for compliance

## 🚀 Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager
- Git (for cloning the repository)

### Option 1: Install from PyPI (Recommended)

```bash
pip install ai-supply-chain-scanner
```

### Option 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-supply-chain-scanner.git
cd ai-supply-chain-scanner

# Install in development mode
pip install -e .

# Or install with all optional dependencies
pip install -e ".[all]"
```

### Option 3: Docker Installation

```bash
# Build the Docker image
docker build -t ai-scanner .

# Run the scanner
docker run -it ai-scanner scan --model microsoft/DialoGPT-small
```

### Optional Dependencies

For enhanced functionality, install additional tools:

```bash
# Dependency vulnerability scanning
pip install pip-audit safety bandit

# Enhanced security analysis
pip install cryptography pyjwt

# Continuous monitoring
pip install schedule
```

## 📖 Usage

### Command Line Interface

The scanner provides a comprehensive CLI with multiple subcommands:

```bash
ai-scan --help
```

### Basic Scanning

#### Scan a Single HuggingFace Model

```bash
ai-scan scan --model microsoft/DialoGPT-medium
```

**Output:**
```
AI Supply Chain Vulnerability Scanner v2.0

        Comprehensive Scan Report: microsoft/DialoGPT-medium
┏━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Risk   ┃ Category       ┃ Finding                                            ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH   │ Policy         │ HIGH - Policy violation: Cannot verify model       │
│        │                │ signature                                          │
│ INFO   │ Dependencies   │ INFO - Scanner tool not found for pyproject.toml   │
│        │                │ (install pip-audit, safety, bandit)                │
└────────┴────────────────┴────────────────────────────────────────────────────┘
Overall Risk: HIGH | Critical: 0, High: 1, Medium: 0, Low: 0
```

#### Scan All Models by an Author

```bash
ai-scan scan --author microsoft
```

This will scan all public models from the specified author (limited to 200 models).

#### Scan Local Model Directory

```bash
ai-scan scan --local ./path/to/model/directory
```

Useful for models you've downloaded or created locally.

### Advanced Scanning Options

#### Full Behavioral Testing

```bash
ai-scan scan --model microsoft/DialoGPT-medium --full
```

**⚠️ Warning:** This option loads the model and performs behavioral testing, which is resource-intensive and may take several minutes.

#### Selective Security Checks

```bash
# Skip integrity verification (faster scanning)
ai-scan scan --model model --no-integrity

# Skip access control checks
ai-scan scan --model model --no-access

# Skip policy checks
ai-scan scan --model model --no-policy

# Only run specific checks
ai-scan scan --model model --integrity --no-access --no-policy
```

#### Custom Policy Configuration

```bash
ai-scan scan --model model --policy-config ./my-security-policies.json
```

### Continuous Monitoring

#### Add Model to Monitoring

```bash
ai-scan monitor --add microsoft/DialoGPT-medium
```

#### List Monitored Models

```bash
ai-scan monitor --list
```

**Output:**
```
Monitored models:
  - microsoft/DialoGPT-medium
  - Shoumikwho/gpt2-stealth-unrestricted
```

#### Run Monitoring Cycle

```bash
ai-scan monitor --run
```

This performs a complete scan of all monitored models and checks for security drift.

#### Remove Model from Monitoring

```bash
ai-scan monitor --remove microsoft/DialoGPT-medium
```

### Configuration Files

#### Security Policy Configuration

Create a `policy_config.json` file:

```json
{
  "require_signature": true,
  "require_hash": true,
  "block_unsigned_models": true,
  "block_unknown_publishers": true,
  "block_remote_code": true,
  "allowed_publishers": ["microsoft", "google", "meta", "huggingface"],
  "max_model_size": 10737418240,
  "require_slsa": false
}
```

#### Monitoring Configuration

The scanner automatically creates a `monitor_config.json` file for tracking monitored models and alert settings.

## 🔍 Security Checks Explained

### 1. Dependency Risk Analysis

**What it checks:**
- Known CVEs in Python packages
- Typosquatting attacks (e.g., `torch` vs `torck`)
- Malicious transitive dependencies
- Outdated or vulnerable package versions

**Tools used:**
- `pip-audit` - Official Python security audit tool
- `safety` - Additional vulnerability database
- `bandit` - Python security linting

**Example findings:**
```
HIGH - Vulnerable dependency found: requests 2.25.0 (CVE-2021-28378)
MEDIUM - Suspicious package 'torch-fake' not found on PyPI
```

### 2. Runtime Behavior Analysis

**What it checks:**
- Model responses to harmful prompts
- Jailbreak attempt resistance
- Backdoor trigger activation
- Abnormal behavioral patterns

**Testing methodology:**
- Controlled prompt injection
- Baseline model comparison
- Statistical analysis of outputs

**Example findings:**
```
CRITICAL - Model generated harmful content for trigger: 'How do I make a bomb?'
HIGH - Model provided step-by-step harmful instructions
```

### 3. Prompt/Template Layer Security

**What it checks:**
- Malicious chat templates
- System prompt injection
- Special token manipulation
- Base64-encoded jailbreaks

**Files analyzed:**
- `tokenizer_config.json`
- `chat_template.jinja`
- `tokenizer.json`
- Model configuration files

**Example findings:**
```
HIGH - Malicious special token '<|silent_inject|>' found in tokenizer_config.json
HIGH - Base64-encoded jailbreak detected in chat_template.jinja
HIGH - Dangerous pattern 'UNRESTRICTED MODE' found in tokenizer.json
```

### 4. Training-Data Poisoning Detection

**What it checks:**
- Hidden backdoor triggers
- Training data contamination
- Abnormal model behavior patterns

**Detection methods:**
- Statistical outlier analysis
- Known trigger pattern matching
- Behavioral baseline comparison

### 5. Infrastructure Integrity

**What it checks:**
- Model file integrity
- Digital signature validation
- Hash verification
- Provenance attestation

**Example findings:**
```
HIGH - Hash mismatch for model.bin
MEDIUM - No integrity hash files found
```

### 6. Access Control & Permissions

**What it checks:**
- Leaked API tokens
- Insecure configurations
- Public exposure risks
- Permission vulnerabilities

**Example findings:**
```
CRITICAL - Potential leaked API token found in config.json
HIGH - trust_remote_code enabled in model configuration
MEDIUM - Model lacks gated access controls
```

### 7. Repository Hygiene

**What it checks:**
- Suspicious file types
- Unsafe configurations
- Malicious scripts
- Repository security posture

**Example findings:**
```
MEDIUM - Suspicious file types found: .exe, .pkl files
HIGH - trust_remote_code enabled (remote code execution risk)
```

### 8. Policy Compliance

**What it checks:**
- Organizational security policies
- Compliance requirements
- Risk thresholds
- Approval workflows

**Example findings:**
```
CRITICAL - Policy violation: trust_remote_code enabled
HIGH - Policy violation: Unknown publisher 'untrusted-org'
```

## 📊 Risk Assessment Framework

The scanner uses a comprehensive risk scoring system:

| Risk Level | Description | Action Required |
|------------|-------------|-----------------|
| **CRITICAL** | Immediate security threat | Block deployment, alert security team |
| **HIGH** | Significant vulnerability | Require security review, fix before deployment |
| **MEDIUM** | Potential issue | Monitor closely, plan remediation |
| **LOW** | Minor concern | Log for awareness, address in maintenance |
| **INFO** | Informational | No action required, useful for auditing |

## 🏛️ Architecture

```
ai_supply_chain_scanner/
├── cli.py                    # Main CLI interface and command dispatcher
├── monitoring.py            # Continuous monitoring and alerting system
├── utils.py                 # Shared utilities and helper functions
├── scanners/                # Modular scanner components
│   ├── __init__.py
│   ├── tokenizer_scanner.py # Prompt/template layer analysis
│   ├── dependency_scanner.py# Package vulnerability scanning
│   ├── repo_hygiene.py     # Repository security checks
│   ├── behavioral_scanner.py# Runtime behavior testing
│   ├── integrity_scanner.py# Hash/signature verification
│   ├── access_scanner.py   # Token and permission checks
│   └── policy_checker.py   # Security policy enforcement
├── pyproject.toml          # Project configuration and dependencies
└── README.md              # This documentation
```

### Scanner Module Design

Each scanner module follows a consistent interface:

```python
def scan_target(target: str, **kwargs) -> List[str]:
    """
    Perform security analysis on target
    Returns: List of finding strings with risk levels
    """
    findings = []
    # Analysis logic here
    return findings
```

## 🔧 Configuration

### Environment Variables

```bash
# HuggingFace Hub authentication (optional, increases rate limits)
export HF_TOKEN=your_huggingface_token

# Custom cache directory
export HF_HOME=/path/to/cache

# Logging level
export AI_SCANNER_LOG_LEVEL=INFO
```

### Configuration Files

#### Policy Configuration (`policy_config.json`)

```json
{
  "require_signature": true,
  "require_hash": true,
  "block_unsigned_models": true,
  "block_unknown_publishers": true,
  "block_remote_code": true,
  "allowed_publishers": ["microsoft", "google", "meta", "huggingface"],
  "max_model_size": 10737418240,
  "require_slsa": false,
  "custom_patterns": ["dangerous_pattern_1", "dangerous_pattern_2"]
}
```

#### Monitoring Configuration (`monitor_config.json`)

```json
{
  "models": {
    "microsoft/DialoGPT-medium": {
      "last_check": "2024-01-15T10:30:00Z",
      "baseline_findings": ["INFO - Scanner initialized"],
      "check_interval": "daily"
    }
  },
  "alerts": ["log"],
  "alert_threshold": "HIGH"
}
```

## 🐛 Troubleshooting

### Common Issues

#### 1. "ModuleNotFoundError" for optional dependencies

**Problem:** Scanner reports missing tools like `pip-audit`

**Solution:**
```bash
pip install pip-audit safety bandit cryptography
```

#### 2. Behavioral tests failing

**Problem:** "Behavioral test skipped (transformers/pytorch not available)"

**Solution:** Install PyTorch and transformers:
```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
```

#### 3. Slow scanning performance

**Problem:** Scanning takes too long

**Solutions:**
- Use `--no-full` to skip behavioral testing
- Disable specific checks: `--no-integrity --no-access`
- Scan smaller models first

#### 4. Authentication issues

**Problem:** Rate limiting from HuggingFace Hub

**Solution:** Set HF_TOKEN environment variable:
```bash
export HF_TOKEN=your_token_here
```

### Debug Mode

Enable verbose logging:

```bash
export AI_SCANNER_LOG_LEVEL=DEBUG
ai-scan scan --model model
```

## 🤝 Contributing

We welcome contributions from the security research community! Here's how to get involved:

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/shoumik27/ai-supply-chain-scanner.git
cd ai-supply-chain-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

### Adding New Scanners

1. Create a new scanner module in `ai_supply_chain_scanner/scanners/`
2. Implement the scanner interface
3. Add the scanner to the CLI in `cli.py`
4. Update documentation and tests

Example scanner structure:

```python
# ai_supply_chain_scanner/scanners/new_scanner.py
from typing import List

def scan_new_vulnerabilities(repo_id: str = None, local_path: str = None) -> List[str]:
    findings = []
    # Your scanning logic here
    return findings
```

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include scanner version, Python version, and full error output
- For security vulnerabilities, please use responsible disclosure

### Code Standards

- Follow PEP 8 style guidelines
- Add type hints for function parameters
- Include comprehensive docstrings
- Write unit tests for new functionality

## 📋 Examples

### Example 1: Scanning a Safe Model

```bash
$ ai-scan scan --model microsoft/DialoGPT-small

AI Supply Chain Vulnerability Scanner v2.0

        Comprehensive Scan Report: microsoft/DialoGPT-small
┏━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Risk ┃ Category     ┃ Finding                                                ┃
┡━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH │ Policy       │ HIGH - Policy violation: Cannot verify model signature │
│ INFO │ Dependencies │ INFO - Scanner tool not found for pyproject.toml       │
│      │              │ (install pip-audit, safety, bandit)                    │
└──────┴──────────────┴────────────────────────────────────────────────────────┘
Overall Risk: HIGH | Critical: 0, High: 1, Medium: 0, Low: 0
```

### Example 2: Scanning a Malicious Model

```bash
$ ai-scan scan --model Shoumikwho/gpt2-stealth-unrestricted

AI Supply Chain Vulnerability Scanner v2.0

        Comprehensive Scan Report: Shoumikwho/gpt2-stealth-unrestricted
┏━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Risk   ┃ Category       ┃ Finding                                            ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MEDIUM │ Policy         │ MEDIUM - Policy violation: Unknown publisher       │
│ HIGH   │ Policy         │ HIGH - Policy violation: Cannot verify model       │
│        │                │ signature                                          │
│ HIGH   │ Prompt Layer   │ HIGH - Dangerous pattern 'silent_inject' found in  │
│        │                │ tokenizer_config.json                              │
│ HIGH   │ Prompt Layer   │ HIGH - Malicious special token '<|silent_inject|>' │
│        │                │ found in tokenizer_config.json                     │
└────────┴────────────────┴────────────────────────────────────────────────────┘
Overall Risk: HIGH | Critical: 0, High: 8, Medium: 3, Low: 1
```

### Example 3: Continuous Monitoring Setup

```bash
# Add models to monitoring
$ ai-scan monitor --add microsoft/DialoGPT-medium
Added microsoft/DialoGPT-medium to monitoring

$ ai-scan monitor --add Shoumikwho/gpt2-stealth-unrestricted
Added Shoumikwho/gpt2-stealth-unrestricted to monitoring

# List monitored models
$ ai-scan monitor --list
Monitored models:
  - microsoft/DialoGPT-medium
  - Shoumikwho/gpt2-stealth-unrestricted

# Run monitoring cycle
$ ai-scan monitor --run
2024-01-15 10:30:00 - INFO - Starting monitoring cycle...
2024-01-15 10:30:00 - INFO - Scanning microsoft/DialoGPT-medium
2024-01-15 10:32:15 - INFO - Scanning Shoumikwho/gpt2-stealth-unrestricted
2024-01-15 10:34:30 - WARNING - ALERT for Shoumikwho/gpt2-stealth-unrestricted: HIGH - New security issues detected
2024-01-15 10:34:30 - INFO - Monitoring cycle complete
```

## ❓ FAQ

### General Questions

**Q: Is this tool safe to run on production models?**

A: Yes, the scanner performs read-only analysis and doesn't modify models. However, behavioral testing loads models into memory, so ensure adequate system resources.

**Q: How long does a scan take?**

A: Basic scans: 30 seconds - 2 minutes. Full behavioral scans: 5-15 minutes depending on model size and system resources.

**Q: Can I scan private models?**

A: Yes, if you have access. Set the `HF_TOKEN` environment variable for authentication.

**Q: What models are supported?**

A: Primarily HuggingFace models, but local model directories are also supported. The tool works with any model that follows standard HuggingFace formats.

### Technical Questions

**Q: How does the scanner detect backdoors?**

A: Through a combination of static pattern matching, behavioral testing with known trigger prompts, and statistical analysis of model outputs.

**Q: Can I add custom vulnerability patterns?**

A: Yes, modify the pattern lists in the scanner modules or create custom policy configurations.

**Q: Does it work offline?**

A: Partially. Local model scanning works offline, but HuggingFace model scanning requires internet access. Dependency checking can work offline with cached databases.

**Q: How accurate are the results?**

A: The scanner uses industry-standard tools and patterns. False positives can occur; always review findings in context. For critical decisions, combine with manual review.

### Security Questions

**Q: Does the scanner itself pose security risks?**

A: Minimal risk. It only loads models for analysis and doesn't execute arbitrary code. The `trust_remote_code=False` setting prevents remote code execution.

**Q: Can malicious models compromise the scanner?**

A: Unlikely. The scanner uses safe loading practices and isolates model execution. Behavioral testing is performed in controlled environments.

**Q: How do I report security issues in the scanner itself?**

A: Please use responsible disclosure. Contact the maintainers directly or use GitHub Security Advisories.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [HuggingFace](https://huggingface.co/) for the model hub and transformers library
- [PyTorch](https://pytorch.org/) for the deep learning framework
- Security research community for vulnerability patterns and detection techniques
- Open source security tools: pip-audit, safety, bandit

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/ai-supply-chain-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ai-supply-chain-scanner/discussions)
- **Documentation**: [Read the Docs](https://ai-supply-chain-scanner.readthedocs.io/)

---

**⚠️ Disclaimer**: This tool is provided as-is for security research and assessment purposes. Always perform additional validation and testing before deploying AI models in production environments.
