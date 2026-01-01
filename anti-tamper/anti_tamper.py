# anti_tamper.py
"""
Lightweight Anti-Tamper (Defensive PoC)

This script illustrates a simple client-side anti-tamper module:
- File integrity verification using SHA-256
- Forbidden process detection (process name / exe / command line)
- Basic anti-debugging check (Windows IsDebuggerPresent)

Configuration:
- Reads ./config.yaml (located next to this script)
- Writes JSONL logs to the configured log directory
- Supported actions:
    - log_only : log events only
    - exit     : log events and terminate the process

Note:
In a real product, enforcement would be handled by the game engine,
launcher, or backend (termination, quarantine, kick, ban, etc.).
This PoC intentionally focuses on detection logic only.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import hashlib
import json
import os
import pathlib
import time
from typing import Any, Callable, Dict, List, Sequence, Tuple

import psutil
import yaml


# ----------------------------
# Hash / Time helpers
# ----------------------------
def sha256_file(path: str) -> str:
    """Compute and return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now_iso() -> str:
    """Return a stable UTC ISO-8601 timestamp for logging."""
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# ----------------------------
# Process / Debug detection
# ----------------------------
def detect_forbidden(needles: Sequence[str]) -> List[Tuple[int, str, str]]:
    """
    Enumerate running processes and return matches.
    A match is a substring found in process name, executable path, or command line.
    """
    found: List[Tuple[int, str, str]] = []

    for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            name = (p.info.get("name") or "").lower()
            exe = (p.info.get("exe") or "").lower()
            cmdline = " ".join(p.info.get("cmdline") or []).lower()

            for needle in needles:
                n = (needle or "").strip().lower()
                if not n:
                    continue

                if n in name or n in exe or n in cmdline:
                    found.append(
                        (int(p.info.get("pid")), p.info.get("name") or "", p.info.get("exe") or "")
                    )
                    break

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return found


def is_debugger_present() -> bool:
    """Windows-only: detect debugger presence using IsDebuggerPresent."""
    try:
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0  # type: ignore[attr-defined]
    except Exception:
        return False


# ----------------------------
# Config / Logging
# ----------------------------
def load_config(path: str) -> Dict[str, Any]:
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def ensure_dir(path: str) -> None:
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


def make_logger(log_dir: str) -> Tuple[Callable[..., None], str]:
    """
    JSONL logger:
    - Writes to antitamper_YYYYMMDD_HHMMSS.log
    - Also prints to stdout (useful for local runs / CI)
    """
    ensure_dir(log_dir)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(log_dir, f"antitamper_{ts}.log")

    def log(event: str, **fields: Any) -> None:
        row = {"ts": utc_now_iso(), "event": event, **fields}
        line = json.dumps(row, ensure_ascii=False)

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        print(line)

    return log, log_path


def sanitize_forbidden(value: Any) -> List[str]:
    """
    Normalize the forbidden_processes list to reduce false positives.
    - Accepts list / string / iterable
    - Filters overly generic or very short terms
    - Deduplicates while preserving order
    """
    if value is None:
        items: List[Any] = []
    elif isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = [value]
    else:
        items = list(value)

    banned_generic = {
        "service",
        "services",
        "windows",
        "system32",
        "program files",
        "programdata",
        "microsoft",
        "security",
        "health",
        "widget",
    }

    cleaned: List[str] = []
    for x in items:
        if x is None:
            continue
        s = str(x).strip().lower()
        if not s:
            continue
        if s in banned_generic:
            continue
        if len(s) < 4:
            continue
        cleaned.append(s)

    out: List[str] = []
    seen = set()
    for s in cleaned:
        if s not in seen:
            out.append(s)
            seen.add(s)

    return out


# ----------------------------
# Response handling
# ----------------------------
def do_action(action: str, log: Callable[..., None], reason: str, details: Dict[str, Any]) -> None:
    """
    Centralized response to a detection event.
    In this PoC: structured logging and optional process termination.
    """
    action_norm = (action or "exit").strip().lower()

    details_out = dict(details)
    details_out["note"] = (
        "In a real game, the engine or launcher would enforce the response "
        "(termination, quarantine, kick, ban, etc.)."
    )

    log("ALERT", reason=reason, action=action_norm, details=details_out)

    if action_norm == "log_only":
        return

    log("EXITING", code=1)
    raise SystemExit(1)


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    base_dir = pathlib.Path(__file__).resolve().parent
    config_path = str(base_dir / "config.yaml")

    cfg = load_config(config_path)

    log_dir = cfg.get("log_dir", "sample_logs")
    log, log_path = make_logger(str(base_dir / log_dir))

    debug = bool(cfg.get("debug", True))

    log("START", config_path=config_path, base_dir=str(base_dir), cwd=os.getcwd(), log_path=log_path)
    if debug:
        log("DEBUG_RAW_CFG_KEYS", keys=sorted(list(cfg.keys())))
        log(
            "DEBUG_RAW_FORBIDDEN",
            raw_type=str(type(cfg.get("forbidden_processes", []))),
            raw_value=cfg.get("forbidden_processes", []),
        )

    target_path_cfg = cfg.get("target_path")
    expected_sha256 = (cfg.get("expected_sha256") or "").strip().lower()
    interval = float(cfg.get("scan_interval_sec", 1.0))
    action = (cfg.get("action") or "exit").strip().lower()
    enable_dbg = bool(cfg.get("enable_debugger_check", True))

    forbidden = sanitize_forbidden(cfg.get("forbidden_processes", []))
    if debug:
        log("DEBUG_FORBIDDEN_SANITIZED", forbidden=forbidden, forbidden_count=len(forbidden))

    if not target_path_cfg:
        log("CONFIG_ERROR", message="target_path is missing")
        raise SystemExit(2)

    target_path = os.path.expandvars(str(target_path_cfg))
    target_path = os.path.expanduser(target_path)
    if not os.path.isabs(target_path):
        target_path = str((base_dir / target_path).resolve())

    log(
        "CONFIG",
        target_path=target_path,
        expected_sha256=expected_sha256,
        forbidden_count=len(forbidden),
        scan_interval_sec=interval,
        action=action,
        enable_debugger_check=enable_dbg,
    )

    if not os.path.exists(target_path):
        log("CONFIG_ERROR", message="target_path does not exist", target_path=target_path)
        raise SystemExit(2)

    if not expected_sha256:
        expected_sha256 = sha256_file(target_path)
        log(
            "EXPECTED_SHA256_EMPTY",
            note="Current hash used as integrity baseline",
            expected_sha256=expected_sha256,
        )

    log("READY")

    while True:
        try:
            current = sha256_file(target_path)
        except Exception as e:
            do_action(action, log, "INTEGRITY_READ_ERROR", {"error": str(e), "target_path": target_path})
            current = None

        if current and current.lower() != expected_sha256:
            do_action(
                action,
                log,
                "INTEGRITY_FAIL",
                {
                    "target_path": target_path,
                    "expected_sha256": expected_sha256,
                    "current_sha256": current,
                },
            )

        if forbidden:
            matches = detect_forbidden(forbidden)
            if matches:
                do_action(
                    action,
                    log,
                    "FORBIDDEN_PROCESS",
                    {
                        "needles": forbidden,
                        "found": [{"pid": pid, "name": name, "exe": exe} for (pid, name, exe) in matches],
                    },
                )

        if enable_dbg and is_debugger_present():
            do_action(action, log, "DEBUGGER_DETECTED", {"method": "IsDebuggerPresent"})

        log("TICK_OK", sha256=current)
        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Bye.")
        raise
