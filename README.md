# roustabout

[![CI](https://github.com/featurecreep-cron/roustabout/actions/workflows/ci.yml/badge.svg)](https://github.com/featurecreep-cron/roustabout/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/featurecreep-cron/roustabout)](https://github.com/featurecreep-cron/roustabout/blob/main/LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://github.com/featurecreep-cron/roustabout)
[![Release](https://img.shields.io/github/v/release/featurecreep-cron/roustabout)](https://github.com/featurecreep-cron/roustabout/releases)

Structured documentation, security auditing, and compose generation for Docker environments.

Roustabout connects to the Docker API, inspects every running container, and produces three kinds of output:

- **Markdown snapshots** — a complete inventory of your Docker host: images, ports, volumes, networks, env vars, labels
- **Security audits** — 10 checks covering socket exposure, secrets in env vars, sensitive ports, missing healthchecks, root containers, restart loops, OOM kills, flat networking, missing restart policies, and stale images
- **Compose generation** — reconstructs a `docker-compose.yml` from running containers, filtering image noise and handling named volumes, network modes, healthchecks, resource limits, capabilities, and devices

All output passes through a secret redactor. Environment variables matching configurable patterns (passwords, tokens, API keys) are replaced with `[REDACTED]` before they reach your screen or your AI model.

## Install

```bash
pip install -e .
```

For MCP server support:

```bash
pip install -e ".[mcp]"
```

## Usage

### CLI

```bash
# Document your Docker environment
roustabout snapshot
roustabout snapshot --show-env --output snapshot.md

# Run security checks
roustabout audit
roustabout audit --output audit.md --hide-accepted

# Generate a compose file from running containers
roustabout generate
roustabout generate --redact --output docker-compose.yml

# Manage audit findings
roustabout accept docker-socket-watchtower "Watchtower needs socket access"
roustabout false-positive secrets-env-nginx "NGINX_HOST is not a secret"
roustabout resolve stale-image-redis "Updated to redis:7.2"
```

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

Default redaction patterns: `password`, `secret`, `token`, `api_key`, `key`, `credential`, `private_key`, `access_key`, `database_url`, `auth`. URLs with embedded credentials (`://user:pass@host`) are always redacted.

## Security Checks

| Check | Default Severity | What it finds |
|-------|-----------------|---------------|
| Docker socket mount | Critical | Containers with `/var/run/docker.sock` |
| Secrets in env vars | Warning | Env var keys matching secret patterns |
| Sensitive ports exposed | Warning | Database, admin, and management ports on 0.0.0.0 |
| Missing healthcheck | Info | Containers without health monitoring |
| Running as root | Info | Containers without a `user` directive |
| Restart loops | Warning | Containers with restart count > 5 |
| OOM killed | Warning | Containers killed by the OOM killer |
| Flat networking | Info | All containers sharing one network |
| Missing restart policy | Info | Containers without restart policy |
| Stale images | Info | Images older than configurable threshold |

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
