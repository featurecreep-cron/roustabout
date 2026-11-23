"""Container exec — run commands inside containers.

Single most requested debugging capability. Two safety models:

- DENYLIST: any command except known escape vectors. ELEVATE keys only.
- ALLOWLIST: only commands the operator listed for that container in
  roustabout.toml. Applies to any key that carries an exec grant for the
  container, and to ELEVATE keys when the container has an allowlist.

A key below ELEVATE cannot exec at all without a grant naming the container.
All output passes through sanitization.
"""

from __future__ import annotations

import dataclasses
import shlex
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
    # User that granted (non-ELEVATE) callers run as. None = container default.
    user: str | None = None


class DeniedCommand(Exception):
    """Command fails the active safety model (allowlist or denylist)."""

    def __init__(self, command: tuple[str, ...], reason: str) -> None:
        self.command = command
        self.reason = reason
        super().__init__(f"Command denied: {reason}")


class ExecConfigError(Exception):
    """The exec configuration exists but cannot be trusted.

    Distinct from "no configuration" (None): a missing allowlist selects the
    denylist for ELEVATE keys, so a config that failed to load must never be
    reported as missing.
    """


class ExecNotPermitted(Exception):
    """The API key may not exec into this container under any safety model."""

    def __init__(self, target: str, tier: str) -> None:
        self.target = target
        self.tier = tier
        super().__init__(
            f"exec into {target!r} requires the elevate tier or an exec grant "
            f"for this container (key tier: {tier})"
        )


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


# An allowlist entry ending in this element permits extra trailing arguments.
ALLOW_TRAILING = "*"


def _entry_matches(entry: str, command: tuple[str, ...]) -> bool:
    """Whether a command matches one allowlist entry, argument by argument.

    The entry is split shell-style into arguments, which must equal the
    command's arguments exactly. A final ``*`` permits any further arguments;
    anywhere else ``*`` is a literal. Comparing whole arguments (rather than a
    string prefix) keeps ``trigger my_dag`` from matching ``trigger my_dag_v2``
    and ``cat /a`` from matching ``cat /a /etc/shadow``.
    """
    try:
        expected = tuple(shlex.split(entry))
    except ValueError:
        return False  # unbalanced quotes — an entry that cannot be read permits nothing

    trailing_ok = len(expected) > 1 and expected[-1] == ALLOW_TRAILING
    if trailing_ok:
        expected = expected[:-1]
    elif expected == (ALLOW_TRAILING,):
        return False  # a bare wildcard would allow every command

    if not expected:
        return False
    if trailing_ok:
        return command[: len(expected)] == expected
    return command == expected


def _check_allowlist(
    command: tuple[str, ...],
    config: ExecConfig | None,
) -> None:
    """Raise DeniedCommand if command doesn't match any allowlist entry."""
    if not command:
        raise DeniedCommand(command, "empty command")

    if not config or not config.allowed:
        raise DeniedCommand(
            command,
            "no exec allowlist configured for this container",
        )

    if any(_entry_matches(entry, command) for entry in config.allowed):
        return

    raise DeniedCommand(
        command,
        "command does not match any allowlist entry",
    )


def load_exec_config(target: str) -> ExecConfig | None:
    """Load exec configuration for a container from roustabout.toml.

    Reads the [exec.<container>] section. Returns None only when the
    configuration loaded cleanly and has no section for this container.

    Raises:
        ExecConfigError: the configuration could not be loaded, or the
            section is malformed. Callers must refuse exec — treating this as
            "no allowlist" would widen an allowlisted container to the denylist.

    Example config:
        [exec.nginx]
        allowed = ["nginx -t", "cat /etc/nginx/nginx.conf", "getent hosts *"]
        user = "nginx"
        timeout = 10
    """
    from roustabout.config import load_config

    try:
        cfg = load_config()
    except Exception as exc:  # noqa: BLE001 — any load failure must fail closed
        raise ExecConfigError(f"cannot load roustabout config: {type(exc).__name__}") from exc

    exec_section = cfg.raw.get("exec", {})
    if not isinstance(exec_section, dict):
        raise ExecConfigError("[exec] must be a table")

    section = exec_section.get(target)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ExecConfigError(f"[exec.{target}] must be a table")

    allowed = section.get("allowed", [])
    if not isinstance(allowed, list) or not all(isinstance(e, str) for e in allowed):
        raise ExecConfigError(f"[exec.{target}] allowed must be a list of strings")

    user = section.get("user")
    if user is not None and not isinstance(user, str):
        raise ExecConfigError(f"[exec.{target}] user must be a string")

    timeout = section.get("timeout", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ExecConfigError(f"[exec.{target}] timeout must be a positive integer")

    return ExecConfig(allowed=tuple(allowed), timeout=timeout, user=user)


def may_exec(*, tier: str, exec_grants: tuple[str, ...], target: str) -> bool:
    """Whether a key may exec into a container at all.

    ELEVATE always may. OBSERVE and OPERATE may only with a grant naming the
    container. Needs no configuration, so it can be answered before (and
    regardless of whether) the exec config loads.
    """
    if tier == "elevate":
        return True
    return tier in ("observe", "operate") and target in exec_grants


def authorize_exec(
    *,
    tier: str,
    exec_grants: tuple[str, ...],
    cmd: ExecCommand,
    config: ExecConfig | None,
) -> tuple[ExecCommand, FrictionMechanism]:
    """Decide whether a key may exec into a container, and under which model.

    - ELEVATE: allowlist if the container has one, otherwise the denylist.
      The caller's user, workdir and timeout are honoured.
    - Any other tier: only if ``exec_grants`` names the container, and always
      under the allowlist — a grant never selects the denylist, so a granted
      container with no allowlist runs nothing. The caller may not choose the
      user or workdir; user and timeout come from the container's config.

    Returns the command to run (with user/timeout fixed for granted callers)
    and the safety model for ``execute()``.

    Raises:
        ExecNotPermitted: the key has neither ELEVATE nor a grant.
        DeniedCommand: a granted caller tried to choose user or workdir.
    """
    if not may_exec(tier=tier, exec_grants=exec_grants, target=cmd.target):
        raise ExecNotPermitted(cmd.target, tier)

    if tier == "elevate":
        if config and config.allowed:
            return cmd, FrictionMechanism.ALLOWLIST
        return cmd, FrictionMechanism.DENYLIST

    if cmd.user is not None or cmd.workdir is not None:
        raise DeniedCommand(
            cmd.command,
            "user and workdir are fixed by the container's exec configuration "
            "for keys below the elevate tier",
        )

    restricted = dataclasses.replace(
        cmd,
        user=config.user if config else None,
        timeout=config.timeout if config else cmd.timeout,
    )
    return restricted, FrictionMechanism.ALLOWLIST


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


def check_command(cmd: ExecCommand, friction: FrictionMechanism) -> None:
    """Apply the safety model to a command without running it.

    execute() calls this first. It is public so a caller can refuse a command
    before opening a Docker connection for it.

    Raises:
        DeniedCommand: the command fails the active safety model.
        ExecConfigError: ALLOWLIST was requested and the config is unreadable.
    """
    if friction == FrictionMechanism.ALLOWLIST:
        _check_allowlist(cmd.command, load_exec_config(cmd.target))
    elif friction == FrictionMechanism.DENYLIST:
        _check_denylist(cmd.command)


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

    Raises:
        DeniedCommand: the command fails the active safety model.
        ExecConfigError: ALLOWLIST was requested and the config is unreadable.
    """
    check_command(cmd, friction)

    # Resolve container
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
