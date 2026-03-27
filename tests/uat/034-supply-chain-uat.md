# UAT Plan: Supply Chain Hardening + Migration Assistant

**LLD:** 034
**Date:** 2026-03-27
**Tester:** Chris
**Prerequisites:** Python 3.13, roustabout develop branch, access to cronbox

---

## Part 1: GitHub Actions SHA Pinning PRs

### 1.1 Roustabout (#21)

- [ ] Review PR diff — confirm every `uses:` line has a SHA + version comment
- [ ] Confirm `codeql.yml` has `contents: read` at top-level permissions
- [ ] Confirm `dependabot.yml` has `cooldown:` blocks on pip ecosystem
- [ ] Confirm `dependabot.yml` has `docker` ecosystem entry
- [ ] Confirm `Dockerfile` both FROM lines have `@sha256:` digest
- [ ] Merge PR
- [ ] Verify CI passes on develop after merge (Actions tab)
- [ ] Trigger a manual scorecard run or wait for Monday schedule — confirm Pinned-Dependencies score improves
- [ ] After next dependabot run: confirm grouped PRs appear with `chore` prefix

### 1.2 Secretscreen (#4)

- [ ] Review PR diff — confirm every `uses:` line has a SHA + version comment
- [ ] Confirm `dependabot.yml` has `cooldown:` blocks and `interval: daily` for pip
- [ ] Merge PR
- [ ] Verify CI passes on main after merge
- [ ] Confirm scorecard Pinned-Dependencies improves

### 1.3 Tandoor-api (#4)

- [ ] Review PR diff — confirm every `uses:` line has a SHA + version comment
- [ ] Confirm `dependabot.yml` has `cooldown:` blocks on github-actions
- [ ] Merge PR
- [ ] Verify CI passes on main after merge
- [ ] Trigger a manual workflow_dispatch on `build-and-publish.yml` (force=true) — confirm it completes with SHA-pinned actions

---

## Part 2: supply_chain.py Module

### Setup

```bash
# On dev machine or cronbox
cd ~/roustabout
git checkout develop && git pull
pip install -e ".[dev]"
```

### 2.1 Compose Audit — Happy Path

Create a test compose file with known issues:

```bash
mkdir -p /tmp/uat-supply-chain
cat > /tmp/uat-supply-chain/docker-compose.yml << 'YAML'
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
YAML
```

```python
python3 -c "
from roustabout.supply_chain import audit_compose
from pathlib import Path

audit = audit_compose(Path('/tmp/uat-supply-chain/docker-compose.yml'))

print(f'Services: {audit.service_count}')
print(f'Migration ready: {audit.migration_ready}')
print(f'Stateful: {audit.stateful_services}')
print(f'Stateless: {audit.stateless_services}')
print()
print('Images:')
for img in audit.images:
    print(f'  {img.service}: {img.image} (pinned={img.is_pinned}, floating={img.is_floating}, pattern={img.tag_pattern})')
print()
print('Secrets found:')
for s in audit.secrets:
    print(f'  {s.service}.{s.field} [{s.pattern_matched}] (is_ref={s.is_reference})')
print()
print('Issues:')
for issue in audit.issues:
    print(f'  - {issue}')
"
```

**Expected results:**
- [ ] `service_count` = 4
- [ ] `migration_ready` = False (inline secrets exist)
- [ ] `stateful_services` includes `db`, `cache` (database images)
- [ ] `stateless_services` includes `web`
- [ ] `app` image flagged as floating (`:latest`)
- [ ] `POSTGRES_PASSWORD`, `SECRET_KEY`, `API_TOKEN` detected as inline secrets
- [ ] `DATABASE_URL` NOT detected as a secret (doesn't match field pattern)
- [ ] `POSTGRES_USER` NOT detected as a secret (not a secret field pattern)
- [ ] No secret VALUES appear in the output

### 2.2 Secret Extraction — Dry Run

```python
python3 -c "
from roustabout.supply_chain import extract_secrets
from pathlib import Path

result = extract_secrets(
    Path('/tmp/uat-supply-chain/docker-compose.yml'),
    dry_run=True,
)

print(f'Secrets to extract: {result.secrets_extracted}')
print(f'Services modified: {result.services_modified}')
print()
print('Sanitized compose (should have no secret values):')
print(result.sanitized_compose)
"
```

**Expected results:**
- [ ] `secrets_extracted` >= 3 (PASSWORD, SECRET_KEY, API_TOKEN)
- [ ] Sanitized compose shows `\${VAR_NAME}` references, not plaintext secrets
- [ ] Original file unchanged (dry run)
- [ ] `hunter2`, `super-secret-key-12345`, `tok_live_abc123def456` do NOT appear in output

### 2.3 Secret Extraction — Live Run

```bash
# Make a copy first
cp /tmp/uat-supply-chain/docker-compose.yml /tmp/uat-supply-chain/docker-compose.yml.manual-backup
```

```python
python3 -c "
from roustabout.supply_chain import extract_secrets
from pathlib import Path

result = extract_secrets(
    Path('/tmp/uat-supply-chain/docker-compose.yml'),
    dry_run=False,
)

print(f'Secrets extracted: {result.secrets_extracted}')
print(f'Env file: {result.env_file}')
print(f'Backup: {result.compose_backup}')
print(f'Services modified: {result.services_modified}')
"
```

Then verify:

```bash
echo "=== .env file (should contain actual secret values) ==="
cat /tmp/uat-supply-chain/.env

echo ""
echo "=== .env permissions (should be 600) ==="
stat -c '%a' /tmp/uat-supply-chain/.env

echo ""
echo "=== Rewritten compose (should have variable refs, no secrets) ==="
cat /tmp/uat-supply-chain/docker-compose.yml

echo ""
echo "=== Backup exists ==="
ls -la /tmp/uat-supply-chain/docker-compose.yml.bak
```

**Expected results:**
- [ ] `.env` file contains the actual secret values (e.g., `DB_POSTGRES_PASSWORD=hunter2`)
- [ ] `.env` permissions are `600`
- [ ] Compose file now has `${DB_POSTGRES_PASSWORD}` instead of `hunter2`
- [ ] Compose file now has `${WEB_SECRET_KEY}` instead of `super-secret-key-12345`
- [ ] `.bak` backup file exists with original content
- [ ] Non-secret env vars (POSTGRES_USER, POSTGRES_DB, APP_NAME) unchanged

### 2.4 Re-audit After Extraction

```python
python3 -c "
from roustabout.supply_chain import audit_compose
from pathlib import Path

audit = audit_compose(Path('/tmp/uat-supply-chain/docker-compose.yml'))
print(f'Migration ready: {audit.migration_ready}')
inline = [s for s in audit.secrets if not s.is_reference]
print(f'Inline secrets remaining: {len(inline)}')
for s in inline:
    print(f'  {s.service}.{s.field}')
"
```

**Expected results:**
- [ ] `migration_ready` = True (all secrets now use variable references)
- [ ] Zero inline secrets remaining

### 2.5 Digest Resolution

```python
python3 -c "
from roustabout.supply_chain import resolve_digests
from pathlib import Path

# Restore original for this test (has real image names)
import shutil
shutil.copy('/tmp/uat-supply-chain/docker-compose.yml.manual-backup',
            '/tmp/uat-supply-chain/docker-compose.yml')

digests = resolve_digests(Path('/tmp/uat-supply-chain/docker-compose.yml'))
for d in digests:
    print(f'{d.service}:')
    print(f'  current: {d.current_image}')
    print(f'  digest:  {d.latest_digest}')
    print(f'  pin_ref: {d.pin_reference}')
    print()
"
```

**Expected results:**
- [ ] `nginx` and `postgres` resolve to `sha256:...` digests from Docker Hub
- [ ] `redis` resolves to a digest
- [ ] `ghcr.io/featurecreep-cron/morsl` resolves to a digest from GHCR
- [ ] `pin_reference` shows the full pinned format (e.g., `nginx:1.25-alpine@sha256:...`)
- [ ] No crashes on network errors (graceful degradation)

### 2.6 Digest Pinning

```python
python3 -c "
from roustabout.supply_chain import resolve_digests, pin_compose_digests
from pathlib import Path

path = Path('/tmp/uat-supply-chain/docker-compose.yml')
digests = resolve_digests(path)
result = pin_compose_digests(path, digests, dry_run=True)

print(f'Images pinned: {result.images_pinned}')
print(f'Images skipped: {result.images_skipped}')
for reason in result.skipped_reasons:
    print(f'  skip: {reason}')
print()
print('Pinned compose:')
print(result.compose_content[:500])
"
```

**Expected results:**
- [ ] `nginx`, `postgres`, `redis` pinned (have specific tags)
- [ ] `morsl` skipped (`:latest` tag — can't meaningfully pin)
- [ ] Skip reason mentions `:latest`
- [ ] Pinned compose content shows `@sha256:...` on pinned images

### 2.7 Renovate Config Generation

```python
python3 -c "
from roustabout.supply_chain import audit_compose, generate_renovate_config
from pathlib import Path
import json

audit = audit_compose(Path('/tmp/uat-supply-chain/docker-compose.yml'))
config = generate_renovate_config(
    audit,
    own_registries=('ghcr.io/featurecreep-cron/',),
    default_cooldown_days=3,
    database_cooldown_days=7,
)

print('=== renovate.json ===')
print(config.config_json)
print()
print('=== Policies ===')
for p in config.policies:
    print(f'{p.package_name}: age={p.minimum_release_age}, automerge={p.automerge}, reason={p.reason}')
print()
print('=== Warnings ===')
for w in config.warnings:
    print(f'  ⚠ {w}')
"
```

**Expected results:**
- [ ] `ghcr.io/featurecreep-cron/morsl` → 0 days, automerge=True (own image)
- [ ] `postgres` → 7 days, automerge=False (stateful/database)
- [ ] `redis` → 7 days, automerge=False (stateful/database)
- [ ] `nginx` → 3 days, automerge=True (third-party stateless)
- [ ] Warning about `:latest` tag on morsl
- [ ] `config_json` is valid JSON with `$schema`, `extends`, `packageRules`
- [ ] `pinDigests: true` in config

### 2.8 Full Round-Trip

Run the complete migration flow on the test compose file:

```python
python3 -c "
from roustabout.supply_chain import (
    audit_compose, extract_secrets, resolve_digests,
    pin_compose_digests, generate_renovate_config,
)
from pathlib import Path
import shutil

# Reset to original
shutil.copy('/tmp/uat-supply-chain/docker-compose.yml.manual-backup',
            '/tmp/uat-supply-chain/docker-compose.yml')
env = Path('/tmp/uat-supply-chain/.env')
if env.exists(): env.unlink()

path = Path('/tmp/uat-supply-chain/docker-compose.yml')

# 1. Audit
a1 = audit_compose(path)
print(f'1. Audit: ready={a1.migration_ready}, secrets={len([s for s in a1.secrets if not s.is_reference])}, unpinned={len([i for i in a1.images if not i.is_pinned])}')

# 2. Extract secrets
ext = extract_secrets(path, dry_run=False)
print(f'2. Extract: {ext.secrets_extracted} secrets moved to .env')

# 3. Resolve digests
digests = resolve_digests(path)
print(f'3. Digests: {len([d for d in digests if d.latest_digest])} resolved')

# 4. Pin
pin = pin_compose_digests(path, digests, dry_run=False)
print(f'4. Pin: {pin.images_pinned} pinned, {pin.images_skipped} skipped')

# 5. Generate Renovate config
a2 = audit_compose(path)
cfg = generate_renovate_config(a2, own_registries=('ghcr.io/featurecreep-cron/',))
Path('/tmp/uat-supply-chain/renovate.json').write_text(cfg.config_json)
print(f'5. Renovate: {len(cfg.policies)} policies, {len(cfg.warnings)} warnings')

# 6. Final audit
a3 = audit_compose(path)
print(f'6. Final: ready={a3.migration_ready}, all_pinned={all(i.is_pinned for i in a3.images if i.tag_pattern != \"latest\")}')
"
```

**Expected results:**
- [ ] Step 1: not ready, has inline secrets, has unpinned images
- [ ] Step 2: secrets extracted (no crash, no secrets in compose)
- [ ] Step 3: digests resolved for Docker Hub and GHCR images
- [ ] Step 4: specific-tagged images pinned, `:latest` skipped
- [ ] Step 5: Renovate config with tiered policies
- [ ] Step 6: migration_ready=True, all non-latest images pinned

---

## Part 3: Edge Cases

### 3.1 Empty compose file

```python
python3 -c "
from roustabout.supply_chain import audit_compose
from pathlib import Path
import tempfile

f = Path(tempfile.mktemp(suffix='.yml'))
f.write_text('services: {}\n')
a = audit_compose(f)
print(f'Services: {a.service_count}, ready: {a.migration_ready}')
f.unlink()
"
```

- [ ] Returns audit with 0 services, migration_ready=True (nothing to migrate)

### 3.2 Already-migrated compose file

```python
python3 -c "
from roustabout.supply_chain import audit_compose
from pathlib import Path
import tempfile

f = Path(tempfile.mktemp(suffix='.yml'))
f.write_text('''services:
  web:
    image: nginx:1.25-alpine@sha256:abc123def456
    environment:
      SECRET_KEY: \${WEB_SECRET}
  db:
    image: postgres:18-alpine@sha256:789xyz
    environment:
      POSTGRES_PASSWORD: \${DB_PASS}
''')
a = audit_compose(f)
print(f'Ready: {a.migration_ready}')
print(f'All pinned: {all(i.is_pinned for i in a.images)}')
print(f'All refs: {all(s.is_reference for s in a.secrets)}')
f.unlink()
"
```

- [ ] migration_ready=True, all images pinned, all secrets are references

### 3.3 Extract secrets is idempotent

```bash
# Reset test file
cp /tmp/uat-supply-chain/docker-compose.yml.manual-backup /tmp/uat-supply-chain/docker-compose.yml
rm -f /tmp/uat-supply-chain/.env
```

```python
python3 -c "
from roustabout.supply_chain import extract_secrets
from pathlib import Path

path = Path('/tmp/uat-supply-chain/docker-compose.yml')

# Run twice
r1 = extract_secrets(path, dry_run=False)
r2 = extract_secrets(path, dry_run=False)

print(f'First run: {r1.secrets_extracted} extracted')
print(f'Second run: {r2.secrets_extracted} extracted')
"
```

- [ ] First run extracts secrets
- [ ] Second run extracts 0 (already variable references)

---

## Cleanup

```bash
rm -rf /tmp/uat-supply-chain
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
