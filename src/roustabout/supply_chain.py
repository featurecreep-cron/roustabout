"""Supply chain migration assistant — compose audit, secret extraction, digest pinning.

Analyzes Docker Compose files for supply chain hardening readiness.
Extracts inline secrets to .env files without exposing values through the API.
Resolves image digests and generates Renovate configuration.

LLD: docs/roustabout/designs/034-supply-chain-migration.md
LLD: docs/roustabout/designs/036-secret-safe-pipeline.md
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from roustabout.models import DockerEnvironment
from roustabout.redactor import sanitize

logger = logging.getLogger(__name__)

_yaml = YAML()
_yaml.preserve_quotes = True
_yaml.width = 4096  # prevent wrapping of long image references after digest pinning


# Secret detection patterns

_SECRET_FIELD_PATTERNS = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AUTH_KEY"
    r"|CREDENTIAL|DB_PASS|MYSQL_ROOT|POSTGRES_PASSWORD"
    r"|REDIS_PASSWORD|SMTP_PASS|MAIL_PASSWORD|ENCRYPTION_KEY"
    r"|JWT_SECRET|AWS_SECRET|AZURE_KEY|GCP_KEY"
    r"|OAUTH_SECRET|OAUTH_CLIENT)",
    re.IGNORECASE,
)

_NOT_SECRET_VALUES = re.compile(
    r"^\$\{.+\}$"  # already a variable reference
    r"|^true$|^false$"
    r"|^\d+$"
    r"|^(localhost|0\.0\.0\.0|127\.0\.0\.1)$",
    re.IGNORECASE,
)

# URI credential pattern: ://user:password@host (catches DATABASE_URL etc.)
_URI_CREDENTIAL_PATTERN = re.compile(r"://[^:/@]+:[^@]+@")

# Database image prefixes — always treat as stateful
_DATABASE_IMAGES = frozenset(
    {
        "postgres",
        "mysql",
        "mariadb",
        "mongo",
        "mongodb",
        "redis",
        "influxdb",
        "clickhouse",
        "cockroachdb",
        "timescaledb",
        "elasticsearch",
        "opensearch",
        "meilisearch",
        "memcached",
        "cassandra",
        "neo4j",
        "couchdb",
    }
)

# Volume mount paths that indicate persistent data
_DATA_PATHS = re.compile(
    r"^/var/lib/(postgresql|mysql|mongodb|redis|elasticsearch)"
    r"|^/data"
    r"|^/opt/.+/data"
    r"|^/bitnami",
)


# Data types


@dataclass(frozen=True)
class ImageReference:
    """An image reference found in a compose file."""

    service: str
    image: str
    tag: str | None
    digest: str | None
    registry: str
    is_pinned: bool
    is_floating: bool
    tag_pattern: str


@dataclass(frozen=True)
class SecretCandidate:
    """An inline value that looks like a secret. Value is never included."""

    service: str
    field: str
    pattern_matched: str
    is_reference: bool


@dataclass(frozen=True)
class VolumeInfo:
    """Volume information for statefulness detection."""

    service: str
    source: str
    target: str
    is_named: bool
    is_data_volume: bool


@dataclass(frozen=True)
class ComposeAudit:
    """Full audit of a compose file for migration readiness."""

    project: str
    file_path: str
    service_count: int
    images: tuple[ImageReference, ...]
    secrets: tuple[SecretCandidate, ...]
    volumes: tuple[VolumeInfo, ...]
    stateful_services: tuple[str, ...]
    stateless_services: tuple[str, ...]
    migration_ready: bool
    issues: tuple[str, ...]


@dataclass(frozen=True)
class ExtractionResult:
    """Result of extracting secrets from a compose file."""

    secrets_extracted: int
    env_file: str
    compose_backup: str
    services_modified: tuple[str, ...]
    sanitized_compose: str


@dataclass(frozen=True)
class DigestInfo:
    """Current and available digest information for an image."""

    service: str
    current_image: str
    current_digest: str | None
    latest_digest: str | None
    latest_tag: str | None
    image_age_hours: int | None
    needs_update: bool
    pin_reference: str



@dataclass(frozen=True)
class PinResult:
    """Result of pinning images in a compose file to digests."""

    images_pinned: int
    images_skipped: int
    compose_content: str
    skipped_reasons: tuple[str, ...]


# Image parsing


def _parse_image(image_str: str) -> tuple[str, str | None, str | None, str]:
    """Parse an image string into (name, tag, digest, registry).

    Examples:
        postgres:18-alpine -> (postgres, 18-alpine, None, docker.io)
        ghcr.io/foo/bar:v1@sha256:abc -> (ghcr.io/foo/bar, v1, sha256:abc, ghcr.io)
        python:3.13-slim@sha256:abc -> (python, 3.13-slim, sha256:abc, docker.io)
    """
    digest = None
    if "@" in image_str:
        image_str, digest = image_str.rsplit("@", 1)

    tag = None
    # Handle tags — but don't split on : in registry prefix (e.g., ghcr.io:443)
    if ":" in image_str:
        parts = image_str.rsplit(":", 1)
        # If the part after : looks like a port number and we have slashes, it's a registry
        if not (parts[1].isdigit() and "/" in parts[0]):
            image_str, tag = parts

    # Determine registry
    if "/" in image_str and "." in image_str.split("/")[0]:
        registry = image_str.split("/")[0]
    else:
        registry = "docker.io"

    return image_str, tag, digest, registry


def classify_tag(tag: str | None) -> str:
    """Classify a Docker image tag pattern.

    Returns: "latest", "semver", "semver-os", "digest", "custom"
    """
    if tag is None:
        return "latest"
    if tag == "latest":
        return "latest"
    if tag.startswith("sha256:"):
        return "digest"

    # semver-os: 18-alpine, 3.13-slim, 3.13-bookworm
    if re.match(r"^\d+(\.\d+)*-[a-z]+\d*$", tag, re.IGNORECASE):
        return "semver-os"

    # semver: 18, 18.3, 18.3.0, v1.2.3
    if re.match(r"^v?\d+(\.\d+)*$", tag):
        return "semver"

    return "custom"


# Compose audit


def audit_compose(project_path: Path) -> ComposeAudit:
    """Analyze a compose file for supply chain migration readiness."""
    with open(project_path) as f:
        content = _yaml.load(f)

    if not isinstance(content, dict):
        msg = f"Invalid compose file: {project_path}"
        raise ValueError(msg)

    services = content.get("services", {})
    project_name = project_path.parent.name

    images: list[ImageReference] = []
    secrets: list[SecretCandidate] = []
    volumes: list[VolumeInfo] = []
    stateful: set[str] = set()
    issues: list[str] = []

    for svc_name, svc_spec in services.items():
        if not isinstance(svc_spec, dict):
            continue

        # Analyze image reference
        image_str = svc_spec.get("image", "")
        if image_str:
            name, tag, digest, registry = _parse_image(str(image_str))
            is_pinned = digest is not None
            is_floating = tag is None or tag == "latest"
            tag_pat = classify_tag(tag)

            images.append(
                ImageReference(
                    service=svc_name,
                    image=str(image_str),
                    tag=tag,
                    digest=digest,
                    registry=registry,
                    is_pinned=is_pinned,
                    is_floating=is_floating,
                    tag_pattern=tag_pat,
                )
            )

            if is_floating:
                issues.append(
                    f"{svc_name}: uses floating tag '{image_str}' — pin to specific version"
                )

            # Check if database image
            base_name = name.rsplit("/", 1)[-1].lower()
            if base_name in _DATABASE_IMAGES:
                stateful.add(svc_name)

        # Analyze environment for secrets
        env = svc_spec.get("environment", {})
        if isinstance(env, dict):
            for key, value in env.items():
                _check_secret(svc_name, key, value, secrets)
        elif isinstance(env, list):
            for item in env:
                if "=" in str(item):
                    key, value = str(item).split("=", 1)
                    _check_secret(svc_name, key, value, secrets)

        # Analyze volumes
        svc_volumes = svc_spec.get("volumes", [])
        if isinstance(svc_volumes, list):
            for vol in svc_volumes:
                vol_info = _parse_volume(svc_name, vol)
                if vol_info:
                    volumes.append(vol_info)
                    if vol_info.is_data_volume:
                        stateful.add(svc_name)

    inline_secrets = [s for s in secrets if not s.is_reference]
    if inline_secrets:
        issues.append(
            f"{len(inline_secrets)} inline secret(s) must be extracted"
            " to .env before committing to git"
        )

    stateless = set(services.keys()) - stateful

    return ComposeAudit(
        project=project_name,
        file_path=str(project_path),
        service_count=len(services),
        images=tuple(images),
        secrets=tuple(secrets),
        volumes=tuple(volumes),
        stateful_services=tuple(sorted(stateful)),
        stateless_services=tuple(sorted(stateless)),
        migration_ready=len(inline_secrets) == 0,
        issues=tuple(issues),
    )


def _check_secret(service: str, key: str, value: Any, secrets: list[SecretCandidate]) -> None:
    """Check if an environment variable looks like a secret.

    Detects secrets by field name pattern (PASSWORD, TOKEN, etc.)
    and by value pattern (credentials embedded in URIs like
    postgresql://user:pass@host/db).
    """
    str_value = str(value) if value is not None else ""

    # Check field name patterns
    match = _SECRET_FIELD_PATTERNS.search(key)
    if match:
        is_ref = bool(_NOT_SECRET_VALUES.match(str_value)) if str_value else True
        secrets.append(
            SecretCandidate(
                service=service,
                field=f"environment.{key}",
                pattern_matched=match.group(1).upper(),
                is_reference=is_ref,
            )
        )
        return

    # Check value for embedded URI credentials
    if str_value and _URI_CREDENTIAL_PATTERN.search(str_value):
        is_ref = bool(_NOT_SECRET_VALUES.match(str_value))
        secrets.append(
            SecretCandidate(
                service=service,
                field=f"environment.{key}",
                pattern_matched="URI_CREDENTIAL",
                is_reference=is_ref,
            )
        )


def _parse_volume(service: str, vol: Any) -> VolumeInfo | None:
    """Parse a volume spec into VolumeInfo."""
    if isinstance(vol, str):
        parts = vol.split(":")
        if len(parts) >= 2:
            source, target = parts[0], parts[1]
            is_named = not source.startswith("/") and not source.startswith(".")
            return VolumeInfo(
                service=service,
                source=sanitize(source) if not is_named else source,
                target=target,
                is_named=is_named,
                is_data_volume=bool(_DATA_PATHS.match(target)),
            )
    elif isinstance(vol, dict):
        source = str(vol.get("source", ""))
        target = str(vol.get("target", ""))
        vol_type = vol.get("type", "volume")
        is_named = vol_type == "volume"
        return VolumeInfo(
            service=service,
            source=sanitize(source) if not is_named else source,
            target=target,
            is_named=is_named,
            is_data_volume=bool(_DATA_PATHS.match(target)),
        )
    return None


# Secret extraction


def extract_secrets(
    project_path: Path,
    env_file: Path | None = None,
    dry_run: bool = False,
) -> ExtractionResult:
    """Extract inline secrets from compose file to .env file.

    Secret values are written to the host filesystem only —
    never returned through the API. The sanitized_compose field
    contains the rewritten compose content with ${VAR} references.
    """
    with open(project_path) as f:
        content = _yaml.load(f)

    if not isinstance(content, dict):
        msg = f"Invalid compose file: {project_path}"
        raise ValueError(msg)

    if env_file is None:
        env_file = project_path.parent / ".env"

    services = content.get("services", {})
    extracted: dict[str, str] = {}
    modified_services: set[str] = set()

    # Read existing .env to avoid clobbering
    existing_env: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                existing_env[k.strip()] = v.strip()

    for svc_name, svc_spec in services.items():
        if not isinstance(svc_spec, dict):
            continue

        env = svc_spec.get("environment")
        if env is None:
            continue

        if isinstance(env, dict):
            _extract_from_dict(svc_name, env, extracted, modified_services)
        elif isinstance(env, list):
            new_list = _extract_from_list(svc_name, env, extracted, modified_services)
            svc_spec["environment"] = new_list

    if not dry_run and extracted:
        # Backup original compose file
        backup_path = project_path.with_suffix(project_path.suffix + ".bak")
        shutil.copy2(project_path, backup_path)

        # Write .env file (append new secrets, preserve existing)
        all_env = {**existing_env, **extracted}
        env_lines = [f"{k}={v}" for k, v in sorted(all_env.items())]
        env_file.write_text("\n".join(env_lines) + "\n")
        env_file.chmod(0o600)

        # Write rewritten compose file
        stream = StringIO()
        _yaml.dump(content, stream)
        project_path.write_text(stream.getvalue())

        # Update .gitignore if in a git repo
        _update_gitignore(project_path.parent, env_file.name)

    # Generate sanitized compose content (safe to return via API)
    stream = StringIO()
    _yaml.dump(content, stream)
    sanitized = stream.getvalue()

    return ExtractionResult(
        secrets_extracted=len(extracted),
        env_file=str(env_file),
        compose_backup=str(project_path.with_suffix(project_path.suffix + ".bak")),
        services_modified=tuple(sorted(modified_services)),
        sanitized_compose=sanitized,
    )


def _is_extractable_secret(key: str, value: Any) -> bool:
    """Check if a key/value pair should be extracted as a secret."""
    str_value = str(value) if value is not None else ""
    if not str_value:
        return False
    if _NOT_SECRET_VALUES.match(str_value):
        return False
    if _SECRET_FIELD_PATTERNS.search(key):
        return True
    if _URI_CREDENTIAL_PATTERN.search(str_value):
        return True
    return False


def _extract_from_dict(
    service: str,
    env: dict[str, str],
    extracted: dict[str, str],
    modified: set[str],
) -> None:
    """Extract secrets from dict-style environment, replacing values in place."""
    for key in list(env.keys()):
        value = env[key]
        if not _is_extractable_secret(key, value):
            continue

        str_value = str(value) if value is not None else ""
        var_name = f"{service.upper()}_{key}"
        extracted[var_name] = str_value
        env[key] = f"${{{var_name}}}"
        modified.add(service)


def _extract_from_list(
    service: str,
    env: list[str],
    extracted: dict[str, str],
    modified: set[str],
) -> list[str]:
    """Extract secrets from list-style environment, returning new list."""
    new_list = []
    for item in env:
        item_str = str(item)
        if "=" not in item_str:
            new_list.append(item)
            continue

        key, value = item_str.split("=", 1)
        if not _is_extractable_secret(key, value):
            new_list.append(item)
            continue

        var_name = f"{service.upper()}_{key}"
        extracted[var_name] = value
        new_list.append(f"{key}=${{{var_name}}}")
        modified.add(service)

    return new_list


def _update_gitignore(directory: Path, env_filename: str) -> None:
    """Add .env to .gitignore if the directory is in a git repo."""
    git_dir = directory
    while git_dir != git_dir.parent:
        if (git_dir / ".git").exists():
            break
        git_dir = git_dir.parent
    else:
        return  # not a git repo

    gitignore = directory / ".gitignore"
    if gitignore.exists():
        existing = gitignore.read_text()
        if env_filename in existing.splitlines():
            return
        gitignore.write_text(existing.rstrip() + f"\n{env_filename}\n")
    else:
        gitignore.write_text(f"{env_filename}\n")


# Digest resolution


def resolve_digests(
    project_path: Path,
    registry_timeout: int = 30,
) -> tuple[DigestInfo, ...]:
    """Resolve current and latest digests for all images in a compose file."""
    audit = audit_compose(project_path)
    results: list[DigestInfo] = []

    for img in audit.images:
        try:
            digest, age_hours = _query_registry_digest(img.image, registry_timeout)
        except Exception:  # noqa: BLE001 — registry errors shouldn't crash audit
            logger.warning("Failed to resolve digest for %s", img.image)
            digest = None
            age_hours = None

        tag = img.tag or "latest"
        name = img.image.split("@")[0]  # strip existing digest
        if ":" not in name:
            name = f"{name}:{tag}"

        pin_ref = f"{name}@{digest}" if digest else name

        results.append(
            DigestInfo(
                service=img.service,
                current_image=img.image,
                current_digest=img.digest,
                latest_digest=digest,
                latest_tag=tag,
                image_age_hours=age_hours,
                needs_update=img.digest != digest if img.digest and digest else digest is not None,
                pin_reference=pin_ref,
            )
        )

    return tuple(results)


def _query_registry_digest(image: str, timeout: int) -> tuple[str | None, int | None]:
    """Query a container registry for the digest of an image.

    Supports Docker Hub and ghcr.io. Returns (digest, age_hours).
    """
    name, tag, _digest, registry = _parse_image(image)
    tag = tag or "latest"

    if registry == "docker.io":
        return _query_docker_hub(name, tag, timeout)
    elif registry == "ghcr.io":
        return _query_ghcr(name, tag, timeout)
    else:
        logger.info("Unsupported registry %s for digest lookup", registry)
        return None, None


def _query_docker_hub(name: str, tag: str, timeout: int) -> tuple[str | None, int | None]:
    """Query Docker Hub for image digest."""
    # Docker Hub library images need "library/" prefix
    if "/" not in name:
        api_name = f"library/{name}"
    else:
        api_name = name

    # Get auth token
    token_url = (
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{api_name}:pull"
    )
    try:
        req = urllib.request.Request(token_url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token_data = json.loads(resp.read())
            token = token_data["token"]
    except (urllib.error.URLError, KeyError, json.JSONDecodeError):
        return None, None

    # Get manifest digest
    manifest_url = f"https://registry-1.docker.io/v2/{api_name}/manifests/{tag}"
    req = urllib.request.Request(
        manifest_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.oci.image.index.v1+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            digest = resp.headers.get("Docker-Content-Digest")
            return digest, None  # Docker Hub doesn't easily expose creation time
    except urllib.error.URLError:
        return None, None


def _query_ghcr(name: str, tag: str, timeout: int) -> tuple[str | None, int | None]:
    """Query GHCR for image digest."""
    # GHCR uses anonymous token for public images
    token_url = f"https://ghcr.io/token?scope=repository:{name.removeprefix('ghcr.io/')}:pull"
    try:
        req = urllib.request.Request(token_url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token_data = json.loads(resp.read())
            token = token_data["token"]
    except (urllib.error.URLError, KeyError, json.JSONDecodeError):
        return None, None

    api_name = name.removeprefix("ghcr.io/")
    manifest_url = f"https://ghcr.io/v2/{api_name}/manifests/{tag}"
    req = urllib.request.Request(
        manifest_url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.oci.image.index.v1+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            digest = resp.headers.get("Docker-Content-Digest")
            return digest, None
    except urllib.error.URLError:
        return None, None


# Compose pinning


def pin_compose_digests(
    project_path: Path,
    digests: tuple[DigestInfo, ...],
    dry_run: bool = False,
) -> PinResult:
    """Rewrite compose file with digest-pinned image references."""
    with open(project_path) as f:
        content = _yaml.load(f)

    if not isinstance(content, dict):
        msg = f"Invalid compose file: {project_path}"
        raise ValueError(msg)

    services = content.get("services", {})
    pinned = 0
    skipped = 0
    skipped_reasons: list[str] = []

    digest_map = {d.service: d for d in digests}

    for svc_name, svc_spec in services.items():
        if not isinstance(svc_spec, dict):
            continue

        info = digest_map.get(svc_name)
        if not info:
            continue

        if not info.latest_digest:
            skipped += 1
            skipped_reasons.append(f"{svc_name}: no digest available from registry")
            continue

        current_image = str(svc_spec.get("image", ""))
        if "@" in current_image:
            skipped += 1
            skipped_reasons.append(f"{svc_name}: already pinned to digest")
            continue

        _, tag, _, _ = _parse_image(current_image)
        if tag is None or tag == "latest":
            skipped += 1
            skipped_reasons.append(f"{svc_name}: uses :latest — pin to specific tag first")
            continue

        svc_spec["image"] = info.pin_reference
        pinned += 1

    stream = StringIO()
    _yaml.dump(content, stream)
    compose_content = stream.getvalue()

    if not dry_run and pinned > 0:
        project_path.write_text(compose_content)

    return PinResult(
        images_pinned=pinned,
        images_skipped=skipped,
        compose_content=compose_content,
        skipped_reasons=tuple(skipped_reasons),
    )



# --- Secret-safe generate-to-extract pipeline (LLD-036) ---


@dataclass(frozen=True)
class MigrationResult:
    """Result of the generate-and-extract pipeline."""

    compose_path: str
    env_file_path: str
    secrets_extracted: int
    env_files_consumed: int
    services: tuple[str, ...]
    warnings: tuple[str, ...]
    dry_run: bool


def generate_and_extract(
    env: DockerEnvironment,
    output_dir: Path,
    *,
    services: list[str] | None = None,
    include_stopped: bool = False,
    dry_run: bool = False,
) -> MigrationResult:
    """Atomic generate + secret extraction pipeline.

    Runs entirely on the host — no secret values cross the API boundary.
    Returns MigrationResult with metadata only, never secret values.
    """
    from roustabout.generator import generate

    output_dir = _validate_output_dir(output_dir)

    compose_yaml = generate(env, include_stopped=include_stopped, services=services)

    compose_path = output_dir / "docker-compose.yml"
    env_file_path = output_dir / ".env"

    # Parse the generated YAML for secret extraction
    yaml_parser = YAML()
    yaml_parser.preserve_quotes = True
    yaml_parser.width = 4096
    content = yaml_parser.load(compose_yaml)

    all_warnings: list[str] = []
    extracted: dict[str, str] = {}
    env_files_consumed = 0
    svc_names: list[str] = []

    if isinstance(content, dict) and "services" in content:
        svc_section = content["services"]

        for svc_name, svc_spec in svc_section.items():
            svc_names.append(svc_name)
            if not isinstance(svc_spec, dict):
                continue

            # Process env_file: directives
            env_file_refs = svc_spec.get("env_file")
            if env_file_refs:
                if isinstance(env_file_refs, str):
                    env_file_refs = [env_file_refs]
                if isinstance(env_file_refs, list):
                    secrets, non_secrets, warnings = _process_env_file_directive(
                        svc_name, env_file_refs, output_dir
                    )
                    all_warnings.extend(warnings)
                    for k, v in secrets.items():
                        extracted[k] = v
                    if non_secrets:
                        env_block = svc_spec.get("environment")
                        if env_block is None:
                            env_block = {}
                            svc_spec["environment"] = env_block
                        if isinstance(env_block, dict):
                            for k, v in non_secrets.items():
                                if k not in env_block:
                                    env_block[k] = v
                    if secrets:
                        env_block = svc_spec.get("environment")
                        if env_block is None:
                            env_block = {}
                            svc_spec["environment"] = env_block
                        if isinstance(env_block, dict):
                            for var_name in secrets:
                                if var_name not in env_block:
                                    env_block[var_name] = f"${{{var_name}}}"
                    del svc_spec["env_file"]
                    env_files_consumed += len(env_file_refs)

            # Extract inline secrets from environment block
            env_block = svc_spec.get("environment")
            if env_block is None:
                continue
            if isinstance(env_block, dict):
                for key in list(env_block.keys()):
                    value = env_block[key]
                    if not _is_extractable_secret(key, value):
                        continue
                    str_value = str(value) if value is not None else ""
                    var_name = f"{svc_name.upper()}_{key}"
                    extracted[var_name] = str_value
                    env_block[key] = f"${{{var_name}}}"
            elif isinstance(env_block, list):
                new_list = []
                for item in env_block:
                    item_str = str(item)
                    if "=" not in item_str:
                        new_list.append(item)
                        continue
                    key, value = item_str.split("=", 1)
                    if not _is_extractable_secret(key, value):
                        new_list.append(item)
                        continue
                    var_name = f"{svc_name.upper()}_{key}"
                    extracted[var_name] = value
                    new_list.append(f"{key}=${{{var_name}}}")
                svc_spec["environment"] = new_list
    else:
        all_warnings.append("No services found in generated output")

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write .env
        if extracted:
            existing: dict[str, str] = {}
            if env_file_path.exists():
                for line in env_file_path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        existing[k.strip()] = v.strip()
            all_env = {**existing, **extracted}
            env_lines = [f"{k}={v}" for k, v in sorted(all_env.items())]
            env_file_path.write_text("\n".join(env_lines) + "\n")
            env_file_path.chmod(0o600)

        # Write compose
        stream = StringIO()
        yaml_parser.dump(content, stream)
        compose_path.write_text(stream.getvalue())

        # Write .gitignore
        _update_gitignore(output_dir, ".env")

    return MigrationResult(
        compose_path=str(compose_path),
        env_file_path=str(env_file_path),
        secrets_extracted=len(extracted),
        env_files_consumed=env_files_consumed,
        services=tuple(sorted(svc_names)),
        warnings=tuple(all_warnings),
        dry_run=dry_run,
    )


def _process_env_file_directive(
    service_name: str,
    env_file_paths: list[str],
    compose_dir: Path,
) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Read env_file: references and classify contents.

    Returns (secrets, non_secrets, warnings) where secrets and non_secrets
    are {key: value} dicts.
    """
    secrets: dict[str, str] = {}
    non_secrets: dict[str, str] = {}
    warnings: list[str] = []

    for env_path_str in env_file_paths:
        env_path = Path(env_path_str)
        if not env_path.is_absolute():
            env_path = compose_dir / env_path

        if not env_path.exists():
            warnings.append(f"{service_name}: env_file '{env_path_str}' not found, skipping")
            continue

        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle export prefix
            if line.startswith("export "):
                line = line[7:]

            # Strip inline comments (but not inside quotes)
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Strip surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]

            # Warn on variable interpolation
            if "${" in value and not _NOT_SECRET_VALUES.match(value):
                warnings.append(
                    f"{service_name}: variable interpolation in '{key}' "
                    f"from '{env_path_str}' — passed through as-is"
                )

            if _is_extractable_secret(key, value):
                secrets[key] = value
            else:
                non_secrets[key] = value

    return secrets, non_secrets, warnings


def _validate_output_dir(output_dir: Path) -> Path:
    """Validate output_dir against path traversal attacks."""
    resolved = output_dir.resolve()
    if ".." in output_dir.parts:
        msg = f"output_dir must not contain '..': {output_dir}"
        raise ValueError(msg)
    return resolved
