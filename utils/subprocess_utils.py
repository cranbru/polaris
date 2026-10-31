import subprocess
from typing import Optional


def run_command(
    command: list[str],
    timeout: int = 120,
    capture_output: bool = True,
    shell: bool = False,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            shell=shell,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {command[0] if command else 'unknown'}"
    except OSError as e:
        return -1, "", f"OS error: {e}"


def run_powershell(script: str, timeout: int = 120) -> tuple[int, str, str]:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    return run_command(command, timeout=timeout)


def run_wmic(query: str, timeout: int = 60) -> tuple[int, str, str]:
    command = ["wmic"] + query.split()
    return run_command(command, timeout=timeout)
