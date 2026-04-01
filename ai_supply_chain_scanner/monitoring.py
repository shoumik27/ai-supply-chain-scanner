import schedule
import time
import json
from pathlib import Path
from typing import Dict, List, Callable
import logging
from datetime import datetime
from .scanners.tokenizer_scanner import scan_tokenizer
from .scanners.dependency_scanner import scan_dependencies
from .scanners.repo_hygiene import scan_repo_hygiene
from .scanners.behavioral_scanner import run_basic_behavioral_test
from .scanners.integrity_scanner import verify_integrity
from .scanners.access_scanner import scan_access_control
from .scanners.policy_checker import check_policies

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ContinuousMonitor:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "monitor_config.json"
        self.monitored_models = {}
        self.alert_callbacks = []
        self.load_config()
    
    def load_config(self):
        if Path(self.config_path).exists():
            with open(self.config_path, "r") as f:
                config = json.load(f)
                self.monitored_models = config.get("models", {})
                self.alert_callbacks = config.get("alerts", [])
    
    def save_config(self):
        config = {
            "models": self.monitored_models,
            "alerts": self.alert_callbacks
        }
        with open(self.config_path, "w") as f:
            json.dump(config, f, indent=2)
    
    def add_model(self, repo_id: str, check_interval: str = "daily"):
        """Add a model to continuous monitoring"""
        self.monitored_models[repo_id] = {
            "last_check": None,
            "baseline_findings": [],
            "check_interval": check_interval
        }
        self.save_config()
    
    def remove_model(self, repo_id: str):
        if repo_id in self.monitored_models:
            del self.monitored_models[repo_id]
            self.save_config()
    
    def scan_model(self, repo_id: str) -> Dict[str, List[str]]:
        """Perform comprehensive scan of a model"""
        findings = {
            "tokenizer": scan_tokenizer(repo_id),
            "dependencies": scan_dependencies(),
            "hygiene": scan_repo_hygiene(repo_id),
            "behavioral": run_basic_behavioral_test(repo_id),
            "integrity": verify_integrity(repo_id),
            "access": scan_access_control(repo_id),
            "policy": check_policies(repo_id)
        }
        return findings
    
    def check_drift(self, repo_id: str, current_findings: Dict[str, List[str]]) -> List[str]:
        """Detect changes in findings (drift detection)"""
        drift_findings = []
        
        if repo_id not in self.monitored_models:
            return drift_findings
            
        baseline = self.monitored_models[repo_id].get("baseline_findings", [])
        
        # Compare current findings with baseline
        current_flat = [f for findings in current_findings.values() for f in findings]
        
        new_findings = [f for f in current_flat if f not in baseline]
        resolved_findings = [f for f in baseline if f not in current_flat]
        
        if new_findings:
            drift_findings.append(f"DRIFT - New security issues detected: {len(new_findings)}")
            for finding in new_findings:
                if "HIGH" in finding or "CRITICAL" in finding:
                    drift_findings.append(f"ALERT - {finding}")
        
        if resolved_findings:
            drift_findings.append(f"DRIFT - Issues resolved: {len(resolved_findings)}")
        
        return drift_findings
    
    def update_baseline(self, repo_id: str, findings: Dict[str, List[str]]):
        """Update baseline findings for drift detection"""
        flat_findings = [f for findings_list in findings.values() for f in findings_list]
        self.monitored_models[repo_id]["baseline_findings"] = flat_findings
        self.monitored_models[repo_id]["last_check"] = datetime.now().isoformat()
        self.save_config()
    
    def run_monitoring_cycle(self):
        """Run one monitoring cycle for all models"""
        logging.info("Starting monitoring cycle...")
        
        for repo_id in self.monitored_models:
            try:
                logging.info(f"Scanning {repo_id}")
                findings = self.scan_model(repo_id)
                
                # Check for drift
                drift = self.check_drift(repo_id, findings)
                
                if drift:
                    self._trigger_alerts(repo_id, drift)
                
                # Update baseline
                self.update_baseline(repo_id, findings)
                
            except Exception as e:
                logging.error(f"Failed to scan {repo_id}: {str(e)}")
        
        logging.info("Monitoring cycle complete")
    
    def _trigger_alerts(self, repo_id: str, alerts: List[str]):
        """Trigger alert callbacks"""
        for callback in self.alert_callbacks:
            try:
                if callback == "log":
                    for alert in alerts:
                        logging.warning(f"ALERT for {repo_id}: {alert}")
                elif callback == "email":
                    # Implement email alerting
                    pass
                # Add more alert types as needed
            except Exception as e:
                logging.error(f"Alert callback failed: {str(e)}")
    
    def start_monitoring(self, interval_minutes: int = 60):
        """Start continuous monitoring"""
        schedule.every(interval_minutes).minutes.do(self.run_monitoring_cycle)
        
        logging.info(f"Starting continuous monitoring (every {interval_minutes} minutes)")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

def monitor_command(repo_id: str = None, add: bool = False, remove: bool = False, list_models: bool = False):
    """CLI command for monitoring functionality"""
    monitor = ContinuousMonitor()
    
    if add and repo_id:
        monitor.add_model(repo_id)
        print(f"Added {repo_id} to monitoring")
    elif remove and repo_id:
        monitor.remove_model(repo_id)
        print(f"Removed {repo_id} from monitoring")
    elif list_models:
        print("Monitored models:")
        for model in monitor.monitored_models:
            print(f"  - {model}")
    else:
        # Run one-time monitoring cycle
        monitor.run_monitoring_cycle()