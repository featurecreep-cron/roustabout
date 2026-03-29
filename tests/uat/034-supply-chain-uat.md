# UAT Plan: Supply Chain Hardening + Migration Assistant

**LLD:** 034
**Date:** 2026-03-27
**Tester:** Chris
**Prerequisites:** roustabout develop branch installed

---

## Part 1: GitHub Actions SHA Pinning PRs

### 1.1 Roustabout (#21)

- [ ] Merge PR
- [ ] CI passes after merge
- [ ] Scorecard Pinned-Dependencies check improves after next run
- [ ] Dependabot creates grouped PRs on next scheduled run

### 1.2 Secretscreen (#4)

- [ ] Merge PR
- [ ] CI passes after merge
- [ ] Scorecard Pinned-Dependencies check improves

### 1.3 Tandoor-api (#4)

- [ ] Merge PR
- [ ] CI passes after merge
- [ ] Trigger a manual workflow_dispatch build — completes successfully

---

## Part 2: supply_chain.py Module

Use the test compose file at the bottom of this document as input. Install roustabout from the develop branch.

### 2.1 Audit a compose file

Using the supply chain module, audit the test compose file.

- [ ] Correctly identifies the number of services
- [ ] Classifies database services as stateful
- [ ] Classifies non-database services as stateless
- [ ] Detects inline secrets by field name pattern
- [ ] Does NOT flag non-secret env vars as secrets
- [ ] Flags floating tags (`:latest` or untagged) as issues
- [ ] Reports `migration_ready=False` when inline secrets exist
- [ ] No secret values appear anywhere in the output

### 2.2 Extract secrets — dry run

Run secret extraction in dry-run mode.

- [ ] Reports how many secrets would be extracted
- [ ] Returns sanitized compose with variable references
- [ ] Original compose file is unchanged on disk
- [ ] No secret values in the returned output

### 2.3 Extract secrets — live

Run secret extraction for real.

- [ ] `.env` file created with the actual secret values
- [ ] `.env` file has restrictive permissions (not world-readable)
- [ ] Compose file rewritten with `${VAR}` references replacing inline secrets
- [ ] Backup of original compose file created
- [ ] Non-secret environment variables left untouched

### 2.4 Re-audit after extraction

Audit the compose file again after secrets have been extracted.

- [ ] `migration_ready` is now True
- [ ] Zero inline secrets remaining

### 2.5 Resolve image digests

Resolve digests for all images in the compose file. (Requires network access.)

- [ ] Docker Hub images resolve to sha256 digests
- [ ] GHCR images resolve to sha256 digests
- [ ] Returns a pin reference string for each image
- [ ] Handles unreachable registries gracefully (no crash)

### 2.6 Pin images to digests

Pin the compose file images to their resolved digests.

- [ ] Images with specific version tags get pinned
- [ ] Images with `:latest` are skipped with a reason
- [ ] Already-pinned images are skipped
- [ ] Dry run mode does not modify the file

### 2.7 Generate Renovate config

Generate a Renovate configuration from the audit results. Specify your own registries.

- [ ] Own-registry images get zero delay and automerge
- [ ] Database/stateful images get longer cooldown and no automerge
- [ ] Third-party stateless images get default cooldown and automerge
- [ ] Warns about images using `:latest` (can't version-track)
- [ ] Output is valid JSON with Renovate schema reference

### 2.8 Full round-trip

Starting from the original test compose file, run the complete flow: audit → extract → resolve → pin → generate config → final audit.

- [ ] Starts not-ready, ends ready
- [ ] All non-latest images pinned at the end
- [ ] Renovate config written with tiered policies
- [ ] No secret values leaked at any step

---

## Part 3: Edge Cases

### 3.1 Empty compose

- [ ] Auditing a compose file with `services: {}` returns 0 services, migration_ready=True

### 3.2 Already-migrated compose

- [ ] Auditing a compose file where all images are digest-pinned and all secrets use `${VAR}` returns migration_ready=True

### 3.3 Idempotent extraction

- [ ] Running extract twice on the same file: first run extracts secrets, second run extracts 0

---

## Test Compose File

```yaml
services:
  web:
    image: nginx:1.25-alpine
    environment:
      APP_NAME: myapp
      SECRET_KEY: super-secret-key-12345
    ports:
      - "8080:80"

  db:
    image: postgres:18-alpine
    environment:
      POSTGRES_PASSWORD: hunter2
      POSTGRES_USER: admin
      POSTGRES_DB: myapp
    volumes:
      - pgdata:/var/lib/postgresql/data

  cache:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  app:
    image: ghcr.io/featurecreep-cron/morsl:latest
    environment:
      API_TOKEN: tok_live_abc123def456
      DATABASE_URL: postgresql://admin:hunter2@db/myapp

volumes:
  pgdata:
  redis_data:
```

---

## Sign-off

| Area | Pass/Fail | Notes |
|------|-----------|-------|
| PR: roustabout #21 | | |
| PR: secretscreen #4 | | |
| PR: tandoor-api #4 | | |
| Compose audit | | |
| Secret extraction | | |
| Digest resolution | | |
| Digest pinning | | |
| Renovate config gen | | |
| Round-trip flow | | |
| Edge cases | | |

**Tester:** _________________ **Date:** _________________
