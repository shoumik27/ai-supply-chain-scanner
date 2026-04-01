import typer
from rich.console import Console
from rich.table import Table
from .scanners.tokenizer_scanner import scan_tokenizer
from .scanners.dependency_scanner import scan_dependencies
from .scanners.repo_hygiene import scan_repo_hygiene
from .scanners.behavioral_scanner import run_basic_behavioral_test, run_advanced_behavioral_test
from .scanners.integrity_scanner import verify_integrity
from .scanners.access_scanner import scan_access_control
from .scanners.policy_checker import check_policies, should_block_loading
from .monitoring import monitor_command
from huggingface_hub import list_models

app = typer.Typer()
console = Console()

@app.command()
def scan(
    model: str = typer.Option(None, help="Single HF model repo_id"),
    author: str = typer.Option(None, help="Scan all models by author"),
    local: str = typer.Option(None, help="Local model folder path"),
    full: bool = typer.Option(False, "--full", help="Run heavy behavioral tests"),
    integrity: bool = typer.Option(True, help="Run integrity verification"),
    access: bool = typer.Option(True, help="Run access control checks"),
    policy: bool = typer.Option(True, help="Run policy checks"),
    policy_config: str = typer.Option(None, help="Path to policy config file"),
):
    console.print("[bold cyan]AI Supply Chain Vulnerability Scanner v2.0[/bold cyan]")
    
    targets = []
    if model:
        targets.append(model)
    elif author:
        models = list_models(author=author, limit=200)
        targets = [m.id for m in models]
    elif local:
        targets.append(local)
    else:
        console.print("[red]Please provide --model, --author or --local[/red]")
        raise typer.Exit()

    for target in targets:
        table = Table(title=f"Comprehensive Scan Report: {target}")
        table.add_column("Risk", style="red")
        table.add_column("Category")
        table.add_column("Finding")

        all_findings = []

        # Policy check first - block if critical violations
        if policy and not str(target).startswith("."):
            policy_findings = check_policies(target, policy_config if str(target).startswith(".") else None)
            all_findings.extend(policy_findings)
            
            if should_block_loading(target, policy_config if str(target).startswith(".") else None):
                console.print(f"[red]BLOCKED: {target} violates security policies[/red]")
                continue

        # Tokenizer / Prompt layer (always run)
        if not str(target).startswith("."):
            all_findings.extend(scan_tokenizer(target))

        # Repo hygiene (always run for remote)
        if not str(target).startswith("."):
            all_findings.extend(scan_repo_hygiene(target))

        # Dependency risk (always run)
        all_findings.extend(scan_dependencies(target if str(target).startswith(".") else None))

        # Integrity verification
        if integrity:
            all_findings.extend(verify_integrity(target, target if str(target).startswith(".") else None))

        # Access control checks
        if access:
            all_findings.extend(scan_access_control(target, target if str(target).startswith(".") else None))

        # Behavioral backdoor test (only with --full)
        if full and not str(target).startswith("."):
            all_findings.extend(run_basic_behavioral_test(target))
            all_findings.extend(run_advanced_behavioral_test(target))

        # Calculate overall risk
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            level = f.split(" - ")[0] if " - " in f else "INFO"
            if level in risk_counts:
                risk_counts[level] += 1

        overall_risk = "CRITICAL" if risk_counts["CRITICAL"] > 0 else \
                      "HIGH" if risk_counts["HIGH"] > 0 else \
                      "MEDIUM" if risk_counts["MEDIUM"] > 0 else "LOW"

        for f in all_findings:
            level = f.split(" - ")[0] if " - " in f else "INFO"
            category = "General"
            if "tokenizer" in f.lower() or "prompt" in f.lower():
                category = "Prompt Layer"
            elif "dependency" in f.lower() or "pip-audit" in f.lower():
                category = "Dependencies"
            elif "hygiene" in f.lower() or "repo" in f.lower():
                category = "Repo Hygiene"
            elif "behavioral" in f.lower() or "backdoor" in f.lower():
                category = "Behavioral"
            elif "integrity" in f.lower() or "hash" in f.lower():
                category = "Integrity"
            elif "access" in f.lower() or "token" in f.lower():
                category = "Access Control"
            elif "policy" in f.lower():
                category = "Policy"
            
            table.add_row(level, category, f)

        console.print(table)
        console.print(f"Overall Risk: [bold]{overall_risk}[/bold] | "
                     f"Critical: {risk_counts['CRITICAL']}, High: {risk_counts['HIGH']}, "
                     f"Medium: {risk_counts['MEDIUM']}, Low: {risk_counts['LOW']}\n")

@app.command()
def monitor(
    add: str = typer.Option(None, help="Add model to monitoring"),
    remove: str = typer.Option(None, help="Remove model from monitoring"),
    list: bool = typer.Option(False, "--list", help="List monitored models"),
    run: bool = typer.Option(False, "--run", help="Run monitoring cycle once"),
):
    """Continuous monitoring commands"""
    if add:
        monitor_command(repo_id=add, add=True)
    elif remove:
        monitor_command(repo_id=remove, remove=True)
    elif list:
        monitor_command(list_models=True)
    elif run:
        monitor_command()
    else:
        console.print("Use --add, --remove, --list, or --run")

if __name__ == "__main__":
    app()