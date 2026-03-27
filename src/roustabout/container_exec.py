"""Container exec — run commands inside containers.

ELEVATE-tier action. Command output is sanitized and truncated.
Commands on the denylist are rejected.

LLD: docs/roustabout/designs/025-container-exec.md
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

import docker.errors
import requests.exceptions

from roustabout.redactor import sanitize
from roustabout.session import DockerSession

logger = logging.getLogger(__name__)

# Size limit for captured output
MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB per stream


# Data types


@dataclass(frozen=True)
class ExecCommand:
    """What to execute inside a container."""

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
    exit_code: int | None  # None if timeout or error before exec
    stdout: str  # sanitized
    stderr: str  # sanitized
    truncated: bool
    error: str | None = None
    timed_out: bool = False


# Command denylist


DENIED_BINARIES: frozenset[str] = frozenset(
    {
        "mount",
        "umount",
        "nsenter",
        "unshare",
        "chroot",
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


class DeniedCommand(Exception):
    """Command matches the denylist."""

    def __init__(self, command: tuple[str, ...], reason: str) -> None:
        self.command = command
        self.reason = reason
        super().__init__(f"Command denied: {reason}")


def _check_denylist(command: tuple[str, ...]) -> None:
    """Raise DeniedCommand if command matches denylist."""
    if not command:
        raise DeniedCommand(command, "empty command")

    binary = command[0].rsplit("/", 1)[-1]
    if binary in DENIED_BINARIES:
        raise DeniedCommand(command, f"binary {binary!r} is on the denylist")

    joined = " ".join(command)
    for pattern in DENIED_PATTERNS:
        if pattern in joined:
            raise DeniedCommand(command, f"command contains denied pattern {pattern!r}")


# Timeout handling


def _exec_with_timeout(
    container: Any,
    exec_kwargs: dict[str, Any],
    timeout: int,
) -> tuple[bool, int | None, bytes | None, bytes | None]:
    """Run exec_run with a timeout. Returns (timed_out, exit_code, stdout, stderr)."""
    result: list[Any] = [None]
    error: list[Exception | None] = [None]

    def _run() -> None:
        try:
            result[0] = container.exec_run(**exec_kwargs)
        except Exception as e:  # noqa: broad-except — capture any docker API error
            error[0] = e

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=timeout)

    if thread.is_alive():
        return True, None, None, None

    if error[0]:
        raise error[0]

    exit_code, output = result[0]
    if isinstance(output, tuple):
        raw_stdout, raw_stderr = output
    else:
        raw_stdout = output
        raw_stderr = None
    return False, exit_code, raw_stdout, raw_stderr


# Output processing


def _process_output(raw: bytes | None) -> tuple[str, bool]:
    """Decode, sanitize, and truncate output."""
    if raw is None:
        return "", False

    truncated = len(raw) > MAX_OUTPUT_BYTES
    if truncated:
        raw = raw[:MAX_OUTPUT_BYTES]

    text = raw.decode("utf-8", errors="replace")
    return sanitize(text), truncated


# Public API


def execute(docker_session: DockerSession, cmd: ExecCommand) -> ExecResult:
    """Execute a command inside a running container.

    The command must not be on the denylist (raises DeniedCommand).
    Output is sanitized and truncated to MAX_OUTPUT_BYTES.
    Commands that exceed the timeout are killed.
    """
    _check_denylist(cmd.command)

    try:
        container = docker_session.client.containers.get(cmd.target)  # type: ignore[attr-defined]
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
