"""Container exec — run commands inside containers.

Single most requested debugging capability. Supports tiered friction:
ALLOWLIST (OPERATE) with per-container command lists, DENYLIST (ELEVATE)
with blocked escape vectors. All output passes through sanitization.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

import docker.errors
import requests.exceptions

from roustabout.permissions import FrictionMechanism
from roustabout.redactor import sanitize
from roustabout.session import DockerSession

# Size limit for captured output
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB per stream (stdout/stderr)


@dataclass(frozen=True)
class ExecCommand:
    """What to run inside a container."""

    target: str
    command: tuple[str, ...]
    user: str | None = None
    workdir: str | None = None
    timeout: int = 30


@dataclass(frozen=True)
class ExecResult:
    """What happened."""

    success: bool
    target: str
    command: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    error: str | None = None
    timed_out: bool = False


@dataclass(frozen=True)
class ExecConfig:
    """Per-container exec configuration from roustabout.toml."""

    allowed: tuple[str, ...] = ()
    pre_mutation: str | None = None
    timeout: int = 30


class DeniedCommand(Exception):
    """Command fails the active safety model (allowlist or denylist)."""

    def __init__(self, command: tuple[str, ...], reason: str) -> None:
        self.command = command
        self.reason = reason
        super().__init__(f"Command denied: {reason}")


# Denylist — blocked binaries and patterns

DENIED_BINARIES: frozenset[str] = frozenset(
    {
        # Shell interpreters — prevent shell wrapper bypass
        "sh",
        "bash",
        "zsh",
        "dash",
        "ash",
        "fish",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        # Shell trampolines — invoke shells indirectly
        "busybox",
        "env",
        "xargs",
        "script",
        "expect",
        # Namespace/container escape
        "mount",
        "umount",
        "nsenter",
        "unshare",
        "chroot",
        # Host-affecting
        "reboot",
        "shutdown",
        "modprobe",
        "insmod",
        "rmmod",
        "iptables",
        "ip6tables",
        "nft",
        "tc",
    }
)

DENIED_PATTERNS: tuple[str, ...] = (
    "/proc/sysrq-trigger",
    "/dev/sd",
    "/dev/nvme",
    "docker.sock",
)


def _check_denylist(command: tuple[str, ...]) -> None:
    """Raise DeniedCommand if command matches denylist."""
    if not command:
        raise DeniedCommand(command, "empty command")

    binary = command[0].rsplit("/", 1)[-1]
    if binary in DENIED_BINARIES:
        raise DeniedCommand(
            command,
            f"binary {binary!r} is on the denylist",
        )

    joined = " ".join(command)
    for pattern in DENIED_PATTERNS:
        if pattern in joined:
            raise DeniedCommand(
                command,
                f"command contains denied pattern {pattern!r}",
            )


def _check_allowlist(
    command: tuple[str, ...],
    config: ExecConfig | None,
) -> None:
    """Raise DeniedCommand if command doesn't match any allowed prefix."""
    if not command:
        raise DeniedCommand(command, "empty command")

    if not config or not config.allowed:
        raise DeniedCommand(
            command,
            "no exec allowlist configured for this container",
        )

    joined = " ".join(command)
    for allowed_prefix in config.allowed:
        if joined.startswith(allowed_prefix):
            return

    raise DeniedCommand(
        command,
        "command does not match any allowed prefix",
    )


def load_exec_config(target: str) -> ExecConfig | None:
    """Load exec configuration for a container from roustabout.toml.

    Stub until config module is implemented. Returns None.
    """
    return None


def _process_output(raw: bytes | None) -> tuple[str, bool]:
    """Decode, sanitize, and truncate output."""
    if raw is None:
        return "", False

    truncated = len(raw) > MAX_OUTPUT_BYTES
    if truncated:
        raw = raw[:MAX_OUTPUT_BYTES]

    text = raw.decode("utf-8", errors="replace")
    return sanitize(text), truncated


def _exec_with_timeout(
    container: Any,
    exec_kwargs: dict[str, Any],
    timeout: int,
) -> tuple[bool, int | None, bytes | None, bytes | None]:
    """Run exec_run with a timeout.

    Returns (timed_out, exit_code, stdout, stderr).
    If timeout expires, returns (True, None, None, None).
    """
    result: list[Any] = [None]
    error: list[Exception | None] = [None]

    def _run() -> None:
        try:
            result[0] = container.exec_run(**exec_kwargs)
        except Exception as e:  # noqa: BLE001 — capture any docker API error for re-raise
            error[0] = e

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=timeout)

    if thread.is_alive():
        return True, None, None, None

    if error[0]:
        raise error[0]

    exit_code, output = result[0]
    if output is None:
        return False, exit_code, None, None
    raw_stdout, raw_stderr = output
    return False, exit_code, raw_stdout, raw_stderr


def execute(
    docker_session: DockerSession,
    cmd: ExecCommand,
    *,
    friction: FrictionMechanism = FrictionMechanism.DENYLIST,
) -> ExecResult:
    """Execute a command inside a running container.

    Friction determines which safety model applies:
    - ALLOWLIST: command must match an entry in the container's exec config
    - DENYLIST: command must not be on the global denylist
    """
    # Safety gate
    if friction == FrictionMechanism.ALLOWLIST:
        config = load_exec_config(cmd.target)
        _check_allowlist(cmd.command, config)
    elif friction == FrictionMechanism.DENYLIST:
        _check_denylist(cmd.command)

    # Resolve container
    try:
        container = docker_session.client.containers.get(cmd.target)
    except docker.errors.NotFound:
        return ExecResult(
            success=False,
            target=cmd.target,
            command=cmd.command,
            exit_code=None,
            stdout="",
            stderr="",
            truncated=False,
            error=f"Container {cmd.target!r} not found",
        )

    # Container must be running
    if container.status != "running":
        return ExecResult(
            success=False,
            target=cmd.target,
            command=cmd.command,
            exit_code=None,
            stdout="",
            stderr="",
            truncated=False,
            error=f"Container is {container.status}, not running",
        )

    # Execute with timeout
    try:
        exec_kwargs: dict[str, Any] = {
            "cmd": list(cmd.command),
            "demux": True,
            "stream": False,
        }
        if cmd.user:
            exec_kwargs["user"] = cmd.user
        if cmd.workdir:
            exec_kwargs["workdir"] = cmd.workdir

        timed_out, exit_code, raw_stdout, raw_stderr = _exec_with_timeout(
            container,
            exec_kwargs,
            cmd.timeout,
        )

        if timed_out:
            return ExecResult(
                success=False,
                target=cmd.target,
                command=cmd.command,
                exit_code=None,
                stdout="",
                stderr="",
                truncated=False,
                error=f"Command timed out after {cmd.timeout}s",
                timed_out=True,
            )

    except docker.errors.APIError as e:
        return ExecResult(
            success=False,
            target=cmd.target,
            command=cmd.command,
            exit_code=None,
            stdout="",
            stderr="",
            truncated=False,
            error=sanitize(str(e)),
        )
    except requests.exceptions.ConnectionError as e:
        return ExecResult(
            success=False,
            target=cmd.target,
            command=cmd.command,
            exit_code=None,
            stdout="",
            stderr="",
            truncated=False,
            error=sanitize(str(e)),
        )

    # Process output
    stdout, stdout_truncated = _process_output(raw_stdout)
    stderr, stderr_truncated = _process_output(raw_stderr)

    return ExecResult(
        success=exit_code == 0,
        target=cmd.target,
        command=cmd.command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        truncated=stdout_truncated or stderr_truncated,
    )
