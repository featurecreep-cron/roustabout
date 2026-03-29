# CHANGELOG

<!-- version list -->

## v0.12.0 (2026-03-29)

### Bug Fixes

- Handle PermissionError in file_ops.read_file
  ([`7e7fffe`](https://github.com/featurecreep-cron/roustabout/commit/7e7fffee11d35c029cfe3d8c13d65af71ebee75d))

### Features

- Add exec, file-read, and file-write CLI commands
  ([`d9e5688`](https://github.com/featurecreep-cron/roustabout/commit/d9e5688495867ae1da5f683feb834fae40bc3222))


## v0.11.0 (2026-03-29)

### Bug Fixes

- Add type annotations to supply_chain helper functions
  ([`d679354`](https://github.com/featurecreep-cron/roustabout/commit/d67935492f46f966ef4f42ecb9aac0b68cf68dd9))

- Address expert review findings across all surfaces
  ([`29ac829`](https://github.com/featurecreep-cron/roustabout/commit/29ac829bf23543a1bb51f105366276bd4b52da4e))

- Detect URI credentials and prevent YAML line wrapping (#22, #23)
  ([`c9176e2`](https://github.com/featurecreep-cron/roustabout/commit/c9176e22e9057f5e1e905b98fb39053db460178a))

- Narrow OAUTH pattern to reduce secret extraction false positives
  ([`99f5564`](https://github.com/featurecreep-cron/roustabout/commit/99f55649a02c37ee8af93d627f5ec7610c54b04e))

- Pass format parameter in remote mode snapshot/audit
  ([#18](https://github.com/featurecreep-cron/roustabout/pull/18),
  [`15a9242`](https://github.com/featurecreep-cron/roustabout/commit/15a924225a9741fea61c073c281f966e4779ef27))

- Remove unused imports in test files (ruff F401)
  ([`093a11b`](https://github.com/featurecreep-cron/roustabout/commit/093a11b291d19fa97872ed3fd90dafb4eb831112))

- Resolve lint errors — import DockerEnvironment, shorten comment line
  ([`226be0a`](https://github.com/featurecreep-cron/roustabout/commit/226be0ab8935fae1ac852099a27a86fda9c3ae4e))

- Resolve mypy type errors in cli, mcp_server, discovery, traefik
  ([`bc9afda`](https://github.com/featurecreep-cron/roustabout/commit/bc9afda4ab4185f29dee8345a5a045299e35cf20))

- Resolve pre-existing lint errors in test files
  ([`6c0b095`](https://github.com/featurecreep-cron/roustabout/commit/6c0b0955f3edbef8a36f40a31595cff0465fed05))

- Resolve pre-existing ruff lint and format errors across codebase
  ([`01b9eab`](https://github.com/featurecreep-cron/roustabout/commit/01b9eabf00109749a4c304ef7a1041a5cd7cd40b))

- Resolve remaining mypy errors in collector, compose_gitops, exec, metrics, manager
  ([`3df32f0`](https://github.com/featurecreep-cron/roustabout/commit/3df32f0da941a4315884ebe645ab14cc340cee5d))

### Chores

- **ci**: Remove obsolete publish.yml
  ([`681b63d`](https://github.com/featurecreep-cron/roustabout/commit/681b63d17ad0071eaea5d4e87f5549c320d8c0b0))

- **deps**: Bump actions/setup-python from 5 to 6 in the actions group
  ([`eec1072`](https://github.com/featurecreep-cron/roustabout/commit/eec107224fe666f3b5ed586c05cab9a1e7eadead))

- **deps**: Bump python from 3.13-slim to 3.14-slim
  ([`926c0f1`](https://github.com/featurecreep-cron/roustabout/commit/926c0f1359821e0456f78ace33b4723fdf4a9149))

- **deps**: Bump the actions group with 3 updates
  ([`4db4fcc`](https://github.com/featurecreep-cron/roustabout/commit/4db4fcc8727aa1d90484135b910b857f076ecaf5))

### Features

- Add --services to generate CLI and migrate command
  ([`7b117a3`](https://github.com/featurecreep-cron/roustabout/commit/7b117a36e9edad4328ca1ee865e6a81c40644d46))

- Implement friction model across gateway, exec, file_ops, compose_apply
  ([`31f2b73`](https://github.com/featurecreep-cron/roustabout/commit/31f2b73148b49ff31b76de41cfe919a4984bd48f))

- Implement friction-based permission model (LLD-005)
  ([`2b89143`](https://github.com/featurecreep-cron/roustabout/commit/2b891430e907a8c662d17ea9c8bb8a6c5fb0c514))

- Implement LLD-035, LLD-036, LLD-037 — stack splitting, secret-safe pipeline, DockStarter import
  ([`596004b`](https://github.com/featurecreep-cron/roustabout/commit/596004bfe334b9412f91dd238155083a660648bd))

- Implement Phase 3 modules (LLD-025 through LLD-033)
  ([`fd1fdda`](https://github.com/featurecreep-cron/roustabout/commit/fd1fdda300151af44c0f9fe836fe2f335ca381e8))

- Implement supply chain migration assistant (LLD-034)
  ([`da17a74`](https://github.com/featurecreep-cron/roustabout/commit/da17a74ec9c571c7e163b39379a411b22e7b4e22))

- Wire network inspection, deep health, and API discovery to surfaces
  ([`c4ce80b`](https://github.com/featurecreep-cron/roustabout/commit/c4ce80b2b165719481c8db9fb7ada68974030caa))

### Refactoring

- Add container filter to collect(), clean up test imports
  ([`a0c5386`](https://github.com/featurecreep-cron/roustabout/commit/a0c5386c2cf2915947ad328d00cf34469912e8a3))

- Generalize dockstarter_env to env_splitter
  ([`af05698`](https://github.com/featurecreep-cron/roustabout/commit/af05698d24ac9c4cfa6a867b6ece07cac2551c30))

- Merge net_check into network_inspect
  ([`3392f6c`](https://github.com/featurecreep-cron/roustabout/commit/3392f6c33d4fa17262d59d40703b4d1b41fa6a55))

- Replace stack splitting with service filter on generate()
  ([`2723149`](https://github.com/featurecreep-cron/roustabout/commit/2723149ce7e89122928586ebe96cb5cc25080495))

### Testing

- Add UAT plan for supply chain migration (LLD-034)
  ([`4c05ec1`](https://github.com/featurecreep-cron/roustabout/commit/4c05ec14d3fbfe55f563e3561341941771a3cfc9))


## v0.10.1 (2026-03-21)

### Bug Fixes

- **ci**: Merge publish into release workflow (GITHUB_TOKEN can't trigger other workflows)
  ([`409bdc0`](https://github.com/featurecreep-cron/roustabout/commit/409bdc05ca2884065d543b3e8013969bb63b0e3c))


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
