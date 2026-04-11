"""
core/executor.py - Command Executor
Chạy tool bên ngoài với timeout, logging, error handling
"""

import subprocess
import logging
import os
import shutil
from typing import Dict, List, Optional, Tuple
import random
import time

logger = logging.getLogger("recon.executor")

_BROKEN_TOOLS: Dict[str, str] = {}
_LOGGED_BROKEN_TOOLS = set()


def _decode_output(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _looks_like_runtime_tool_breakage(stdout: str, stderr: str) -> bool:
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    if "traceback (most recent call last):" not in combined:
        return False
    markers = (
        "modulenotfounderror",
        "importerror",
        "no module named",
        "cannot import name",
        "pkg_resources",
        "distributionnotfound",
    )
    return any(marker in combined for marker in markers)


def _mark_tool_broken(tool: str, reason: str):
    if not tool:
        return
    _BROKEN_TOOLS[tool] = (reason or "runtime failure")[:200]
    if tool not in _LOGGED_BROKEN_TOOLS:
        logger.warning(f"[EXEC] Disabling {tool} for the rest of this run: {_BROKEN_TOOLS[tool]}")
        _LOGGED_BROKEN_TOOLS.add(tool)


def add_evasion(cmd: List[str]) -> List[str]:
    """Add evasion techniques: random delay, user-agent
    
    BUG 13 FIX: Only apply evasion delay to active-attack tools, not passive recon/scanning
    """
    # Active-attack tools that need evasion (trigger WAF/IDS)
    EVASION_TOOLS = {"sqlmap", "dalfox", "nuclei", "ffuf"}
    
    tool_name = cmd[0] if cmd else ""
    
    # Only apply delay for active-attack tools
    if tool_name in EVASION_TOOLS:
        delay = random.randint(1, 3)
        time.sleep(delay)
        logger.debug(f"[EVASION] Applied {delay}s delay for {tool_name}")

    # Add user-agent if curl (for passive tools too)
    if tool_name == "curl":
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
    if tool in _BROKEN_TOOLS:
        reason = _BROKEN_TOOLS.get(tool, "runtime failure")
        logger.warning(f"[EXEC] Skipping disabled tool {tool}: {reason}")
        return -4, "", reason

    resolved_tool = shutil.which(tool)
    if not resolved_tool:
        for candidate in (
            os.path.expanduser(f"~/go/bin/{tool}"),
            os.path.expanduser(f"~/.local/bin/{tool}"),
        ):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                resolved_tool = candidate
                break
    if not resolved_tool:
        msg = f"Tool not found: {tool} (install it or add to PATH)"
        logger.warning(f"[EXEC] {msg}")
        return -1, "", msg
    cmd[0] = resolved_tool

    cmd_str = " ".join(str(c) for c in cmd)
    logger.info(f"[EXEC] Running: {cmd_str}")

    # Add evasion
    cmd = add_evasion(cmd)

    try:
        use_binary_stdin = stdin_data is not None
        input_payload = stdin_data.encode("utf-8") if use_binary_stdin else None
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=not use_binary_stdin,
            timeout=timeout,
            input=input_payload,
            env=env or os.environ.copy(),
            cwd=cwd
        )

        stdout = _decode_output(result.stdout).strip()
        stderr = _decode_output(result.stderr).strip()

        if result.returncode == 0:
            logger.info(f"[EXEC] ✓ {tool} finished (lines: {len(stdout.splitlines())})")
        else:
            if _looks_like_runtime_tool_breakage(stdout, stderr):
                _mark_tool_broken(tool, stderr or stdout or f"exit code {result.returncode}")
            logger.warning(f"[EXEC] ✗ {tool} exited {result.returncode}: {stderr[:200]}")

        if output_file and stdout:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w") as f:
                f.write(stdout)
            logger.debug(f"[EXEC] Output saved to {output_file}")

        return result.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        logger.error(f"[EXEC] TIMEOUT after {timeout}s: {cmd_str}")
        
        # Fallback cho các tool crawl - không làm dừng pipeline
        if tool in ["katana", "hakrawler", "gau", "waybackurls"]:
            logger.warning(f"[EXEC] {tool} timeout, using cached/archived data instead")
            return -2, "", f"Timeout after {timeout}s"
        
        return -2, "", f"Timeout after {timeout}s"
    except Exception as e:
        logger.error(f"[EXEC] Exception running {tool}: {e}")
        
        # Xử lý đặc biệt cho arjun
        if tool == "arjun":
            error_msg = str(e).lower()
            if "argument" in error_msg or "exit code -2" in error_msg:
                logger.warning(f"[EXEC] Arjun argument error - likely malformed URL, skipping")
                return 0, "", ""
        
        return -3, "", str(e)


def tool_available(name: str) -> bool:
    """Check if a CLI tool is available"""
    if name in _BROKEN_TOOLS:
        return False
    if shutil.which(name) is not None:
        return True
    extra_candidates = [
        os.path.expanduser(f"~/go/bin/{name}"),
        os.path.expanduser(f"~/.local/bin/{name}"),
    ]
    return any(os.path.isfile(p) and os.access(p, os.X_OK) for p in extra_candidates)


def check_tools(tools: List[str]) -> dict:
    """Check multiple tools and return availability status"""
    status = {}
    for tool in tools:
        broken_reason = _BROKEN_TOOLS.get(tool)
        if broken_reason:
            status[tool] = False
            logger.info(f"[TOOLS] ✗ {tool} (disabled: {broken_reason[:80]})")
            continue
        available = tool_available(tool)
        status[tool] = available
        icon = "✓" if available else "✗"
        logger.info(f"[TOOLS] {icon} {tool}")
    return status
