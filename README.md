# roustabout

[![CI](https://github.com/featurecreep-cron/roustabout/actions/workflows/ci.yml/badge.svg)](https://github.com/featurecreep-cron/roustabout/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/featurecreep-cron/roustabout)](https://github.com/featurecreep-cron/roustabout/blob/main/LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://github.com/featurecreep-cron/roustabout)
[![Release](https://img.shields.io/github/v/release/featurecreep-cron/roustabout)](https://github.com/featurecreep-cron/roustabout/releases)

Structured documentation, security auditing, and compose generation for Docker environments.

Roustabout connects to the Docker API, inspects every running container, and produces three kinds of output:

- **Markdown snapshots** — a complete inventory of your Docker host: images, ports, volumes, networks, env vars, labels
- **Security audits** — 18 checks covering socket exposure, secrets in env vars, sensitive ports, missing healthchecks, root containers, restart loops, OOM kills, flat networking, missing restart policies, stale images, image age, log rotation, resource limits, and daemon configuration
- **Compose generation** — reconstructs a `docker-compose.yml` from running containers, filtering image noise and handling named volumes, network modes, healthchecks, resource limits, capabilities, devices, logging, read-only filesystems, and dependency inference
- **Snapshot diffs** — compare two JSON snapshots to see what changed: added/removed containers, image updates, env changes, port remapping

All output passes through a secret redactor. Environment variables matching configurable patterns (passwords, tokens, API keys) are replaced with `[REDACTED]` before they reach your screen or your AI model.

## Install

```bash
pip install roustabout
```

For MCP server support:

```bash
pip install "roustabout[mcp]"
```

## Usage

### CLI

```bash
# Document your Docker environment
roustabout snapshot
roustabout snapshot --show-env --output snapshot.md
roustabout snapshot --format json --output snapshot.json

# Filter by compose project
roustabout snapshot --project mystack
roustabout audit --project mystack

# Run security checks
roustabout audit
roustabout audit --output audit.md --hide-accepted
roustabout audit --format json

# Generate a compose file from running containers
roustabout generate
roustabout generate --redact --output docker-compose.yml

# Compare two snapshots
roustabout diff snapshot-old.json snapshot-new.json

# Manage audit findings
roustabout accept docker-socket-watchtower "Watchtower needs socket access"
roustabout false-positive secrets-env-nginx "NGINX_HOST is not a secret"
roustabout resolve stale-image-redis "Updated to redis:7.2"
```

### Example: Audit Output

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
...

### secrets-in-env — 17 containers, 38 findings

| Container | Exposed Variables |
|-----------|-------------------|
| authentik_server | `AUTHENTIK_EMAIL__PASSWORD`, `AUTHENTIK_SECRET_KEY` |
| grafana | `GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET` |
| mariadb | `MARIADB_PASSWORD`, `MARIADB_ROOT_PASSWORD` |
| photoprism | `PHOTOPRISM_ADMIN_PASSWORD`, `PHOTOPRISM_DATABASE_PASSWORD` |
...

**Fix:** Use Docker secrets, a mounted file, or a secrets manager instead
of environment variables for sensitive values.
```

Findings are grouped by category — each explanation appears once, not per container.

### MCP Server

Roustabout includes an MCP server for use with Claude Code and other AI tools. Five read-only tools, all auto-redacted:

| Tool | Description |
|------|-------------|
| `docker_snapshot` | Full markdown inventory |
| `docker_audit` | Security findings |
| `docker_container` | Single container detail |
| `docker_networks` | Network topology |
| `docker_generate` | Compose file generation |

Run standalone:

```bash
roustabout-mcp
```

Or configure in Claude Code's MCP settings:

```json
{
  "mcpServers": {
    "roustabout": {
      "command": "roustabout-mcp"
    }
  }
}
```

## Configuration

Create `roustabout.toml` in your working directory:

```toml
# Show environment variables in snapshot output
show_env = false

# Show container labels
show_labels = true

# Output file path
output = "docker-snapshot.md"

# Connect to a remote Docker host
docker_host = "tcp://myhost:2375"

# Additional secret patterns (extend defaults, never replace)
redact_patterns = ["my_custom_secret", "internal_token"]

# Override finding severities
[severity_overrides]
"docker-socket" = "info"
"secrets-env" = "critical"
```

Default redaction patterns: `password`, `passwd`, `passphrase`, `secret`, `token`, `api_key`, `apikey`, `credential`, `private_key`, `access_key`, `secret_key`. URLs with embedded credentials (`://user:pass@host`) get partial redaction (password only). Known secret formats (AWS keys, GitHub PATs, JWTs, Stripe keys) are caught by value shape regardless of key name.

## Security Checks

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

## Requirements

- Python 3.10+
- Access to a Docker socket (local or remote)

## Contributing

Bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting. Run `ruff check .` and `ruff format --check .` before submitting.

## Support

If you find roustabout useful, consider [buying us a coffee](https://buymeacoffee.com/featurecreep).

## License

MIT
