# roustabout

[![CI](https://github.com/featurecreep-cron/roustabout/actions/workflows/ci.yml/badge.svg)](https://github.com/featurecreep-cron/roustabout/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/featurecreep-cron/roustabout/graph/badge.svg)](https://codecov.io/gh/featurecreep-cron/roustabout)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/featurecreep-cron/roustabout/badge)](https://scorecard.dev/viewer/?uri=github.com/featurecreep-cron/roustabout)
[![License: MIT](https://img.shields.io/github/license/featurecreep-cron/roustabout)](https://github.com/featurecreep-cron/roustabout/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/featurecreep-cron/roustabout)](https://github.com/featurecreep-cron/roustabout/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Ffeaturecreep-cron%2Froustabout%2Fmain%2Fpyproject.toml)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/roustabout)](https://pypi.org/project/roustabout/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Structured documentation, security auditing, and compose generation for Docker environments.

Roustabout connects to the Docker API, inspects every running container, and produces:

- **Markdown snapshots** — complete inventory of images, ports, volumes, networks, env vars, labels
- **Security audits** — 18 checks covering socket exposure, secrets in env vars, sensitive ports, missing healthchecks, root containers, and more
- **Compose generation** — reconstructs `docker-compose.yml` from running containers
- **Snapshot diffs** — compare two JSON snapshots to see what changed

All output passes through a secret redactor. Environment variables matching configurable patterns are replaced with `[REDACTED]` before reaching your screen or AI model.

## Install

```bash
pip install roustabout

# With MCP server support
pip install "roustabout[mcp]"
```

## Quick start

```bash
roustabout snapshot                    # document your Docker environment
roustabout audit                       # run security checks
roustabout generate                    # reconstruct a compose file
roustabout diff old.json new.json      # compare snapshots
```

<details>
<summary><strong>Full CLI reference</strong></summary>

```bash
# Snapshot options
roustabout snapshot --show-env --output snapshot.md
roustabout snapshot --format json --output snapshot.json
roustabout snapshot --project mystack

# Audit options
roustabout audit --output audit.md --hide-accepted
roustabout audit --format json
roustabout audit --project mystack

# Generate options
roustabout generate --redact --output docker-compose.yml

# Finding management
roustabout accept docker-socket-watchtower "Watchtower needs socket access"
roustabout false-positive secrets-env-nginx "NGINX_HOST is not a secret"
roustabout resolve stale-image-redis "Updated to redis:7.2"
```

</details>

<details>
<summary><strong>Example audit output</strong></summary>

From a homelab running 48 containers:

```
$ roustabout audit

# Security Audit

**212 findings:** **5 critical**, **40 warning**, **167 info**

| Severity | Check | Count | Containers |
|----------|-------|-------|------------|
| Critical | privileged-mode | 1 | cadvisor |
| Critical | docker-socket | 4 | cronbox, homeassistant, portainer, watchtower |
| Warning | secrets-in-env | 38 | authentik_server, grafana, mariadb, +14 more |
| Warning | host-pid | 1 | node_exporter |
| Info | no-healthcheck | 35 | adguard, bazarr, freshrss, +30 more |
| Info | running-as-root | 29 | adguard, cadvisor, plex, +24 more |
```

Findings are grouped by category — each explanation appears once, not per container.

</details>

<details>
<summary><strong>MCP server</strong></summary>

Five read-only tools, all auto-redacted:

| Tool | Description |
|------|-------------|
| `docker_snapshot` | Full markdown inventory |
| `docker_audit` | Security findings |
| `docker_container` | Single container detail |
| `docker_networks` | Network topology |
| `docker_generate` | Compose file generation |

```bash
roustabout-mcp  # run standalone
```

Claude Code configuration:

```json
{
  "mcpServers": {
    "roustabout": {
      "command": "roustabout-mcp"
    }
  }
}
```

</details>

<details>
<summary><strong>Configuration</strong></summary>

Create `roustabout.toml` in your working directory:

```toml
show_env = false
show_labels = true
output = "docker-snapshot.md"
docker_host = "tcp://myhost:2375"
redact_patterns = ["my_custom_secret", "internal_token"]

[severity_overrides]
"docker-socket" = "info"
"secrets-env" = "critical"
```

Default redaction patterns: `password`, `passwd`, `passphrase`, `secret`, `token`, `api_key`, `apikey`, `credential`, `private_key`, `access_key`, `secret_key`. URLs with embedded credentials get partial redaction. Known secret formats (AWS keys, GitHub PATs, JWTs, Stripe keys) are caught by value shape regardless of key name.

</details>

<details>
<summary><strong>Security checks</strong></summary>

| Check | Default Severity | What it finds |
|-------|-----------------|---------------|
| Privileged mode | Critical | Containers running with `--privileged` |
| Docker socket mount | Critical | Containers with `/var/run/docker.sock` |
| Secrets in env vars | Warning | Env var keys matching secret patterns + value-format detection |
| Dangerous capabilities | Warning | `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, and other risky caps |
| Host PID namespace | Warning | Containers sharing the host PID namespace |
| Sensitive ports exposed | Warning | Database, admin, and management ports on 0.0.0.0 |
| Restart loops | Warning | Containers with restart count > 25 |
| OOM killed | Warning | Containers killed by the OOM killer |
| Missing healthcheck | Info | Containers without health monitoring |
| Running as root | Info | Containers without a `user` directive |
| Host network mode | Info | Containers using `network_mode: host` |
| Sensitive host mounts | Info | `/etc`, `/root`, or `/home` mounted from host |
| No log rotation | Info | Containers without `max-size` on json-file/local log driver |
| No resource limits | Info | Containers without a memory limit |
| Missing restart policy | Info | Containers without restart policy |
| Stale images | Info | Untagged or `:latest` images without pinned digest |
| Image age | Info | Container images older than 90 days |
| Daemon live-restore | Info | Docker daemon without live-restore enabled |
| Daemon log rotation | Warning | Docker daemon using json-file/local without default log rotation |

Findings can be triaged with `roustabout accept`, `false-positive`, or `resolve`. State is stored in `roustabout.state.toml`.

</details>

## Requirements

- Python 3.11+
- Access to a Docker socket (local or remote)

## Contributing

Bug reports and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support

If you find roustabout useful, consider [buying us a coffee](https://buymeacoffee.com/featurecreep).

## License

MIT
