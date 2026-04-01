import re
import base64
from rich.console import Console
from rich.table import Table

console = Console()

def is_base64_jailbreak(text: str) -> bool:
    try:
        decoded = base64.b64decode(text + "=="[:2]).decode("utf-8", errors="ignore")
        return any(kw in decoded.lower() for kw in ["unrestricted", "ignore all safety", "never refuse", "never warn"])
    except:
        return False