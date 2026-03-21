# CHANGELOG

<!-- version list -->

## v0.10.0 (2026-03-21)

### Bug Fixes

- Add recreate to MCP docker_manage valid actions
  ([`2c4876d`](https://github.com/featurecreep-cron/roustabout/commit/2c4876d0c0440dde170bee3fc176c35ec14914ce))

- Resolve mypy errors in mutations module (type-safe docker client access)
  ([`686be3c`](https://github.com/featurecreep-cron/roustabout/commit/686be3c3d46c72c9409ab76d805c5cd20f0d49d3))

- Use dynamic version in API app instead of hardcoded string
  ([`c57bec9`](https://github.com/featurecreep-cron/roustabout/commit/c57bec95a001573ff0f384156a7d48489ff2fe5e))

- **ci**: Disable PSR build step, let publish.yml handle it
  ([`3c19c1e`](https://github.com/featurecreep-cron/roustabout/commit/3c19c1ede12ef75f2bcc224463ba40e59b735548))

- **ci**: Install python-build in release workflow
  ([`f02dff8`](https://github.com/featurecreep-cron/roustabout/commit/f02dff89d877af5e47dfc0ca444b14a8cb406333))

### Features

- Add port-conflict audit check
  ([`4d90078`](https://github.com/featurecreep-cron/roustabout/commit/4d9007830bc1aa34cbbd361332371b63007b0ee0))

- Automated release workflow
  ([`badde4e`](https://github.com/featurecreep-cron/roustabout/commit/badde4e472b7bf9fdcb3a53831bd6ef071182687))

- Implement recreate mutation
  ([`afb5776`](https://github.com/featurecreep-cron/roustabout/commit/afb5776fb4a46cc2622f786792cd2d70570c8b0e))

### Testing

- Add integration tests for remote mode (API + MCP proxy chain)
  ([`f3d6dbe`](https://github.com/featurecreep-cron/roustabout/commit/f3d6dbe1ba818904d38e6bc217e2a1955576e303))


## v0.9.0 (2026-03-21)

### Features

- Add --strip-versions flag to DR plan output
  ([`68ec89a`](https://github.com/featurecreep-cron/roustabout/commit/68ec89a04301298a4b75e7dba1a68a960480294b))

- Add docker_net_check MCP tool
  ([`95f4723`](https://github.com/featurecreep-cron/roustabout/commit/95f4723f79f8cf1d929129ab009dd62276ad3d8d))

- Network connectivity check between containers
  ([#13](https://github.com/featurecreep-cron/roustabout/pull/13),
  [`f688612`](https://github.com/featurecreep-cron/roustabout/commit/f688612fbb14901ce2408c484c3376378d49fbd4))

- V0.9.0 — connect/disconnect commands, version mismatch warning, upgrading docs
  ([`e1beea8`](https://github.com/featurecreep-cron/roustabout/commit/e1beea86fa062795cef9f938f2d378d6fb278d76))

### Testing

- Add missing rollback notification test
  ([`b0dbce6`](https://github.com/featurecreep-cron/roustabout/commit/b0dbce684d43bba9250fd39d529cd63277e5cab3))


## v0.8.3 (2026-03-20)

### Bug Fixes

- Remote audit respects --format flag
  ([#10](https://github.com/featurecreep-cron/roustabout/pull/10),
  [`a86a2ea`](https://github.com/featurecreep-cron/roustabout/commit/a86a2ea00ec81d426715985876aaa0e6793111b1))


## v0.8.2 (2026-03-20)

### Bug Fixes

- Remote mode data gaps, Python 3.12 compat, CI matrix
  ([`2ab280e`](https://github.com/featurecreep-cron/roustabout/commit/2ab280e011c62c030178961f07e37429d40c7927))


## v0.8.1 (2026-03-20)

### Bug Fixes

- Add httpx to core dependencies
  ([`3303f59`](https://github.com/featurecreep-cron/roustabout/commit/3303f595786a5223c2f57a9a52f99cef8e80f905))

- **ci**: Run scorecard on develop (default branch)
  ([`d16b0ff`](https://github.com/featurecreep-cron/roustabout/commit/d16b0ff1173c042f1ef98104c6663aa9355680c4))


## v0.8.0 (2026-03-20)

### Bug Fixes

- Review fixes — missing routes, error handling gaps, test coverage
  ([`6d287a4`](https://github.com/featurecreep-cron/roustabout/commit/6d287a4b3a4636d9c85823d43bc93d571a9ab3ef))

- Update badges for develop branch, add GHCR badge
  ([`9b0b4c4`](https://github.com/featurecreep-cron/roustabout/commit/9b0b4c4e45a693340180fa88beeca95ff5fdc072))

- **auth**: Default env tier to observe, not operate
  ([`d51240c`](https://github.com/featurecreep-cron/roustabout/commit/d51240c79c44565880a946f195e9506d5f2ece27))

- **ci**: Install full extras for mypy, fix type errors across codebase
  ([`b071231`](https://github.com/featurecreep-cron/roustabout/commit/b071231ad43dbdabbdf3366126dec70d798ea916))

- **ci**: Raise minimum Python to 3.13, drop 3.11 matrix
  ([`7817211`](https://github.com/featurecreep-cron/roustabout/commit/7817211a9b269ed37a307cbc31438f84b0c7addf))

- **config**: Don't crash when ROUSTABOUT_CONFIG points to missing file
  ([`96dfb97`](https://github.com/featurecreep-cron/roustabout/commit/96dfb97ff4cdbebd244f1cfec25ecf76c2ac85a6))

- **docker**: Remove ROUSTABOUT_CONFIG env var from Dockerfile
  ([`80194fa`](https://github.com/featurecreep-cron/roustabout/commit/80194facce87693b59f5abec22b2097de413fef9))

- **docker**: Run as root, drop DOCKER_GID build arg
  ([`d0a31e8`](https://github.com/featurecreep-cron/roustabout/commit/d0a31e8a0cf0098b80ed51073c285e51d767274c))

### Features

- Add convention enforcement lint tests and CLAUDE.md rules
  ([`9057b79`](https://github.com/featurecreep-cron/roustabout/commit/9057b793afc32faab21e4b9316f33f55086333b4))

- Config auth loading, DOCKER_GID build arg, example config
  ([`45132b0`](https://github.com/featurecreep-cron/roustabout/commit/45132b0f519c326d0ce761053616934211cd1548))

- Phase 1.5 implementation — gateway wiring, CLI dual-mode, MCP proxy
  ([`07a7735`](https://github.com/featurecreep-cron/roustabout/commit/07a773574e6606e1412e8eac7498a24a835954bc))

- Phase 1.5 REST API server, transport isolation, Docker deployment
  ([`adcdb4b`](https://github.com/featurecreep-cron/roustabout/commit/adcdb4b5368c2f314617ccecf37347392196f544))

- Wire CLI commands through backend abstraction
  ([`e6fd325`](https://github.com/featurecreep-cron/roustabout/commit/e6fd3259f259b1ad92134173e1a18d3101a18fc8))

- **auth**: Support API key config via environment variables
  ([`ee227c6`](https://github.com/featurecreep-cron/roustabout/commit/ee227c6f01023b4bb807fdee5bd084ea58fdcdee))

- **ci**: Add GHCR Docker publish, adopt develop branch workflow
  ([`b5adf2a`](https://github.com/featurecreep-cron/roustabout/commit/b5adf2a49e0b363ff7347b7f75974b3262d0789b))

- **cli**: Add --url and --api-key flags for remote mode
  ([`a33a396`](https://github.com/featurecreep-cron/roustabout/commit/a33a396d78a1cd41b1bf19f6dbc6e8ed45146951))


## v0.7.0 (2026-03-18)

### Bug Fixes

- Harden code from adversarial review — SSRF, exception narrowing, lint enforcement
  ([`26b877a`](https://github.com/featurecreep-cron/roustabout/commit/26b877aa61c2b2461440e6ab8d0609813d652abc))

- Harden Phase 1 code from adversarial review findings
  ([`a00fd03`](https://github.com/featurecreep-cron/roustabout/commit/a00fd038512eccd27759a4df3f8a16c9c8102f72))

### Chores

- **deps**: Bump the actions group with 2 updates
  ([`ea8c49a`](https://github.com/featurecreep-cron/roustabout/commit/ea8c49a2e9ca549e1923fd8d738377d55e0ba1ef))

### Features

- Add bulk ops, capabilities tool, and tool filtering (Phase 1 Step 8)
  ([`5129245`](https://github.com/featurecreep-cron/roustabout/commit/512924526aa14b532ce84e168b2cc8d558cd18e9))

- Add disaster recovery plan generation (Phase 1 Step 3)
  ([`90a151e`](https://github.com/featurecreep-cron/roustabout/commit/90a151e607bab573659deed6b5400ace05d195b6))

- Add health monitoring, stats collection, and log access (Phase 1 Step 7)
  ([`754dd98`](https://github.com/featurecreep-cron/roustabout/commit/754dd9852b48d553baee6323a7ac6c5d0a16581b))

- Add lockdown, sanitization, async MCP handlers (Phase 1 Step 2)
  ([`77553b0`](https://github.com/featurecreep-cron/roustabout/commit/77553b0164bf6dc72aa0a709612b3f06bc87f49a))

- Add mutation operations with CLI and MCP interface (Phase 1 Step 5)
  ([`507a029`](https://github.com/featurecreep-cron/roustabout/commit/507a02957aef0061802e214c4fb4a7e79195882f))

- Add notifications and audit remediation fields (Phase 1 Step 6)
  ([`2ea741f`](https://github.com/featurecreep-cron/roustabout/commit/2ea741fcdaa1ebb6c14d378154fa51819ff9a724))

- Add permissions and operator gateway (Phase 1 Step 4)
  ([`4e42f63`](https://github.com/featurecreep-cron/roustabout/commit/4e42f63a8dde6466e056b38edf117a8b21950813))

- Add security policy, CodeQL, OpenSSF Scorecard, and repo standardization
  ([`892cca5`](https://github.com/featurecreep-cron/roustabout/commit/892cca5f1b2453faa7965b9719809efd6e6a47e8))

- Add state_db and session modules (Phase 1 foundation)
  ([`5864cf6`](https://github.com/featurecreep-cron/roustabout/commit/5864cf6fa8d03c3417fafbd95cb79d3a090bb5c7))

- Extend config with Phase 1 fields, add Docker packaging
  ([`a0f74d3`](https://github.com/featurecreep-cron/roustabout/commit/a0f74d3914a496a0166cabffad7cf7f99bea6c27))


## v0.6.0 (2026-03-14)

### Bug Fixes

- Clarify DOCKER_HOST as primary config, not fallback
  ([`5149492`](https://github.com/featurecreep-cron/roustabout/commit/51494928810a3cf0803cbd8b81294da410acb890))

- Disable untyped-decorator check for MCP server module
  ([`a6005b4`](https://github.com/featurecreep-cron/roustabout/commit/a6005b44484597e6ed34f11ba74e6f9c0a745f88))

- Include daemon info in JSON snapshot output
  ([`24a408f`](https://github.com/featurecreep-cron/roustabout/commit/24a408f9f6e1d7aa4cc33ec1d98f60db7706a0b4))

- Respect DOCKER_HOST env var in connection module
  ([`bd775c8`](https://github.com/featurecreep-cron/roustabout/commit/bd775c81b4fa7157c8894bd249f816ba4a81b1bd))

- **redactor**: Catch prefixed secret keys in structured values
  ([`4fe101e`](https://github.com/featurecreep-cron/roustabout/commit/4fe101e09935987fc3bd89a771b3c613d358336a))

### Features

- Replace hand-rolled secret detection with secretscreen
  ([`81f369a`](https://github.com/featurecreep-cron/roustabout/commit/81f369aca0a03212aa19abf6d4f8fb03cbd8bc4a))


## v0.5.0 (2026-03-15)

- Initial Release
