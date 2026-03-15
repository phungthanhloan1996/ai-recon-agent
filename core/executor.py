"""
core/executor.py - Command Executor
Chạy tool bên ngoài với timeout, logging, error handling
"""

import subprocess
import logging
import os
import shutil
from typing import List, Optional, Tuple
import random
import time

logger = logging.getLogger("recon.executor")


def add_evasion(cmd: List[str]) -> List[str]:
    """Add evasion techniques: random delay, user-agent"""
    # Random delay 1-5 seconds
    delay = random.randint(1, 5)
    time.sleep(delay)
    logger.debug(f"[EVASION] Slept {delay}s")

    # Add user-agent if curl
    if cmd[0] == "curl":
        ua = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
        ])
        cmd.extend(["-H", f"User-Agent: {ua}"])

    return cmd


def run_command(
    cmd: List[str],
    timeout: int = 300,
    output_file: Optional[str] = None,
    stdin_data: Optional[str] = None,
    env: Optional[dict] = None,
    cwd: Optional[str] = None
) -> Tuple[int, str, str]:
    """
    Run an external command.
    Returns (returncode, stdout, stderr)
    """
    tool = cmd[0]
    
    # Check tool availability
    if not shutil.which(tool):
        msg = f"Tool not found: {tool} (install it or add to PATH)"
        logger.warning(f"[EXEC] {msg}")
        return -1, "", msg

    cmd_str = " ".join(str(c) for c in cmd)
    logger.info(f"[EXEC] Running: {cmd_str}")

    # Add evasion
    cmd = add_evasion(cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
            env=env or os.environ.copy(),
            cwd=cwd
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode == 0:
            logger.info(f"[EXEC] ✓ {tool} finished (lines: {len(stdout.splitlines())})")
        else:
            logger.warning(f"[EXEC] ✗ {tool} exited {result.returncode}: {stderr[:200]}")

        if output_file and stdout:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w") as f:
                f.write(stdout)
            logger.debug(f"[EXEC] Output saved to {output_file}")

        return result.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        logger.error(f"[EXEC] TIMEOUT after {timeout}s: {cmd_str}")
        return -2, "", f"Timeout after {timeout}s"
    except Exception as e:
        logger.error(f"[EXEC] Exception running {tool}: {e}")
        return -3, "", str(e)


def tool_available(name: str) -> bool:
    """Check if a CLI tool is available"""
    return shutil.which(name) is not None


def check_tools(tools: List[str]) -> dict:
    """Check multiple tools and return availability status"""
    status = {}
    for tool in tools:
        available = tool_available(tool)
        status[tool] = available
        icon = "✓" if available else "✗"
        logger.info(f"[TOOLS] {icon} {tool}")
    return status