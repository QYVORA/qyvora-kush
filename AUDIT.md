# AUDIT.md — qyvora-kush

**Comprehensive capability audit, gap analysis and conformance review.**

- **Repository:** `products/QYVORA-AI/frameworks/qyvora-kush`
- **Audit date:** 2026-10-21
- **Governing prompt:** `products/QYVORA-AI/PROMPT.md`
- **Audit type:** Static, read-only, evidence-based. No feature implementation.
- **Method note:** Every claim below is either **VERIFIED** (source read, binary
  executed, or test run in this session) or **INFERRED** (traced from source but
  not executed). They are distinguished inline.

---

## 1. Framework identity and intended domain

Kush is QYVORA's **offline malware sample analysis framework**. Its domain is
static, deterministic analysis of a *sample document* (a read-only JSON model of
an analyzed artifact) — never execution of a live sample on the developer host.

VERIFIED evidence:

- `README.md:1-6` — "Offline malware sample analysis framework … without ever
  executing the sample."
- `internal/malware/malware.go:1-11` — package doc: "kush never executes an
  unknown sample on the developer host. Analysis is purely static over the sample
  document; behavioral analysis is only represented as observed data from a
  sandbox that MUST NOT run here."
- `bin/kush version -o json` reports `"framework": "kush"`, `"version":
  "v0.1.0"` (VERIFIED, executed this session).
- Ecosystem doc (`knowledge/.../QYVORA-SECURITY-FRAMEWORK-ECOSYSTEM.md:96`) —
  "Kush | Malware analysis | Offline malware sample analysis".

The domain boundary is deliberate and central to the framework's safety model:
`kush.dynamic` (dynamic execution) is declared **not implemented** and refused
honestly (`internal/capabilities/capabilities.go:105-107`,
`internal/malware/detect.go:200-202`).

---

## 2. Audit scope and evidence sources

**Scope.** Full read-only audit of the kush repository: CLI surface, capability
contract, internal packages, analysis rules, pipeline, evidence/risk/reporting
subsystems, CLI/repository layout, tests, and conformance with the QYVORA common
layer and AI orchestration requirements.

**Evidence sources (all accessed this session):**

| Source | Path | How used |
|---|---|---|
| Governing prompt | `products/QYVORA-AI/PROMPT.md` | Read fully (statutes, priorities, statuses) |
| README | `frameworks/qyvora-kush/README.md` | Purpose, commands, rules |
| Docs | `frameworks/qyvora-kush/docs/` | Documentation accuracy |
| Capability contract | `internal/capabilities/capabilities.go` | Machine contract |
| Capability output | `bin/kush capabilities -o json` | VERIFIED runtime |
| Sample model | `internal/malware/malware.go` | Domain model |
| Detection helpers | `internal/malware/detect.go` | Static analysis primitives |
| Rules | `internal/rules/rules.go`, `internal/rules/builtin/builtin.go` | KSH-001…KSH-014 |
| Pipeline | `internal/pipeline/pipeline.go` | Staged engine |
| Validation / target | `internal/validation/validation.go`, `internal/target/manager.go` | Preflight, target model |
| Events | `internal/events/events.go` | JSONL envelope |
| Exit codes | `internal/exitcode/exitcode.go` | 0/1/2/130 |
| Safety model | `internal/safety/safety.go` | Operation metadata |
| Reporting | `internal/reporting/reporting.go` | Report writer |
| Help capture | `docs/audit/help/kush.txt` | Reference help |
| Common layer | `shared/qyvora-common/contract/contract.go`, `.../conformance/runner.go` | Contract + runner |
| Tests | `go test ./... -count=1`, `go vet ./...` | VERIFIED |

**Non-destructive binary probes executed (VERIFIED):**

```
bin/kush version -o json            → exit 0, JSON identity block
bin/kush capabilities -o json       → exit 0, 10 capability records
bin/kush nosuchcmd                  → exit 2  (usage)
bin/kush --nosuchflag               → exit 2  (usage)
bin/kush exploit                    → exit 2, "exploit has no modules in this framework"
bin/kush assess --sim -o json --events off --no-report  → exit 0, 16 findings
```

Git status at audit start: **clean working tree** on `main`, HEAD `c369ac8`.

---

## 3. Existing capability inventory

The machine contract (`bin/kush capabilities -o json`, VERIFIED) publishes ten
capability records and eight command records. Mapping each to source:

| Capability ID | Name | Declared | Source evidence |
|---|---|---|---|
| `kush.intake` | sample intake | implemented, not live | `internal/malware/malware.go:177-212` (`Load`/`LoadFile`) |
| `kush.hashing` | sample hashing | implemented, not live | `internal/malware/malware.go:60,73-77`; hashes carried on the sample model |
| `kush.metadata` | metadata extraction | implemented, not live | `internal/malware/malware.go:80-91`; `Metadata` struct |
| `kush.static` | static analysis | implemented, not live | `internal/malware/detect.go` (whole file) |
| `kush.strings` | strings analysis | implemented, not live | `internal/malware/malware.go:117-122`; `Str` + `NotableStrings` `detect.go:190-198` |
| `kush.behavior` | behavioral surface | implemented, **live** | `internal/malware/malware.go:124-132`; reads sandbox observations only |
| `kush.network` | network indicators | implemented, not live | `internal/malware/malware.go:134-140`; `C2Indicators` `detect.go:100-116` |
| `kush.ioc` | IOC extraction | implemented, not live | `internal/malware/malware.go:142-150`; `VerifiedIOCs` `detect.go:133-175` |
| `kush.classify` | threat classification | implemented, not live | `internal/malware/malware.go:152-160`; `Threat` struct |
| `kush.dynamic` | dynamic execution | **not implemented**, live | `internal/malware/detect.go:200-202`; refused |

**Analysis rules (14), VERIFIED present in `internal/rules/builtin/builtin.go`:**

KSH-001 (suspicious imports, high), KSH-002 (packed/high-entropy, medium),
KSH-003 (unsigned, medium), KSH-004 (persistence, high), KSH-005 (C2, critical),
KSH-006 (encoded launcher, high), KSH-007 (embedded payload, medium),
KSH-008 (user-agent impersonation, medium), KSH-009 (socket+process access,
medium), KSH-010 (verified IOC catalog, informational), KSH-011 (behavioral
anomalies, high), KSH-012 (dynamic execution refused, low), KSH-013 (process
injection primitives, high), KSH-014 (writable-executable section, medium).

**Unit-level detection primitives** (`internal/malware/detect.go`, VERIFIED):
`SuspiciousImports`, `InjectionImports`, `WritableExecutableSections`, `Packed`,
`EncodedCommandExists`, `C2Indicators`, `HighConfidenceIOCs`, `VerifiedIOCs`,
`UnverifiedRiskItems`, `NotableStrings`.

---

## 4. Capability status matrix

| Capability | Status | Evidence (file:line) |
|---|---|---|
| Sample document intake (JSON) | IMPLEMENTED | `internal/malware/malware.go:177-212` |
| Input size bounding (64 MiB) | IMPLEMENTED | `internal/malware/malware.go:175,179-186,208-210` |
| Hashing (as modelled) | IMPLEMENTED | `internal/malware/malware.go:60,73-77` |
| Metadata extraction (as modelled) | IMPLEMENTED | `internal/malware/malware.go:79-91` |
| Deterministic simulation sample | IMPLEMENTED | `internal/malware/simulate.go:10-60` |
| Static analysis (14 rules) | IMPLEMENTED | `internal/rules/builtin/builtin.go` |
| Strings classification | IMPLEMENTED | `internal/malware/malware.go:117-122`; `detect.go:190-198` |
| Behavioral surface (sandbox-read) | PARTIALLY IMPLEMENTED | `internal/malware/malware.go:124-132,174-187`; model exists, no sandbox connector shipped |
| Network indicator extraction | IMPLEMENTED | `internal/malware/detect.go:100-116` |
| IOC extraction + verification | IMPLEMENTED | `internal/malware/detect.go:118-175` |
| Threat classification | IMPLEMENTED | `internal/malware/malware.go:152-160` |
| Risk scoring | IMPLEMENTED | `internal/risk/risk.go` (166 lines, tested) |
| Staged pipeline engine | IMPLEMENTED | `internal/pipeline/pipeline.go:55-90` |
| Evidence store (owner-only) | IMPLEMENTED | `internal/evidence/evidence.go:33-49` |
| Report rendering (md/json/yaml/html) | IMPLEMENTED | `internal/reporting/reporting.go:15-40` |
| Target manager (snapshot/simulation) | IMPLEMENTED | `internal/target/manager.go:96-135` |
| Preflight validation | IMPLEMENTED | `internal/validation/validation.go:29-70` |
| JSONL event stream | IMPLEMENTED | `internal/events/events.go:1-33` |
| Exit-code contract 0/1/2/130 | IMPLEMENTED | `internal/exitcode/exitcode.go:8-13` |
| Dynamic execution | MISSING (refused by design) | `internal/malware/detect.go:200-202`; contract `capabilities.go:105-107` |
| Host execution of sample | MISSING (refused by design) | `internal/safety/safety.go:OpHostExecution`; `Implemented()` `:71` |
| Live provider collection | MISSING | `internal/validation/validation.go:52-60` ("live provider collection is not implemented") |
| Disassembly / advanced code analysis | NOT APPLICABLE | Domain is offline sample-document triage; no disassembler shipped |
| Exploit / active validation | NOT APPLICABLE | `exploit` tier is empty by design (`internal/cli/cli.go:222-229`) |

---

## 5. Reconnaissance and discovery findings

Kush's "reconnaissance" is **sample-document intake and source enumeration**, not
network discovery.

- **Sample intake (VERIFIED):** `malware.Load`/`LoadFile` parse a JSON sample
  document, enforce a schema tag (`qyvora.kush.sample.v1`,
  `internal/malware/malware.go:22,187-189`) and a supported source
  (`internal/malware/malware.go:190-192`).
- **Source inventory (VERIFIED):** `bin/kush sources -o json` /
  `capabilities.RenderSources` lists five offline sources (package, url-drop,
  email-attachment, removable-media, network-share) implemented, and a `live`
  source explicitly not implemented (`internal/capabilities/capabilities.go:141-155`).
- **Environment-aware prerequisite detection:** present but narrow — preflight
  checks snapshot file existence and target type
  (`internal/validation/validation.go:35-70`); there is no OS/tool/dependency
  probe analogous to mansa's hardware report. **Status: PARTIALLY IMPLEMENTED.**
- **Notable strings as indicators:** `detect.go:190-198` classifies strings by
  kind (ip/url/domain/registry/path/command/api/mutex/wildcard)
  (`internal/malware/malware.go:120`).

No network or host discovery exists, and none is appropriate: the domain is
offline. This is **NOT APPLICABLE with justification**, not a gap.

---

## 6. Analysis and assessment findings

**Static analysis (IMPLEMENTED).** `internal/malware/detect.go` implements
recognisable static primitives:

- Suspicious import detection (`:8-22`), injection primitives (`:27-40`),
  W^X section detection (`:44-58`), packer/entropy detection (`:61-71`),
  encoded-command detection with token-aware matching (`:76-95`), C2 indicators
  (`:100-116`), high-confidence and corroborated IOC selection (`:119-175`).
- The encoded-command matcher explicitly avoids prefix-collision false positives
  (`detect.go:73-85` comment, "the previous substring test mis-flagged").
  **This is a documented false-positive-reduction measure — VERIFIED in source.**

**IOC verification (IMPLEMENTED).** `VerifiedIOCs` (`detect.go:133-175`) only
asserts an IOC as verified when its value is corroborated by an independent
in-sample surface (hashes, embedded hashes, strings, network, behavior detail).
The `README.md:24-26` claim matches the code.

**Behavioral analysis (PARTIALLY IMPLEMENTED / HONEST DEGRADATION).** The
`Behavior` model (`internal/malware/malware.go:124-132`) carries observations
whose `Observed` flag distinguishes real sandbox observations from modelled
ones; `UnverifiedRiskItems` (`detect.go:179-187`) surfaces the unobserved ones
honestly. KSH-011 grades behavioral anomalies, and KSH-012 records the
dynamic-execution refusal. No sandbox connector is shipped, so behavior is only
as rich as the supplied sample document. **INFERRED**: there is no code path that
runs a sample to *produce* behavior.

**Threat classification (IMPLEMENTED):** `Threat` struct with family/type/
severity/confidence/scores/summary (`malware.go:152-160`).

**Risk scoring (IMPLEMENTED):** `internal/risk/risk.go` (166 lines) with a
matching test (`internal/risk/risk_test.go`, 158 lines). VERIFIED to run:
`assess --sim` returns a score and level (`... "score": ..., "level": ...`
observed in JSON probe).

---

## 7. Exploitation-related capability findings

Kush has **no exploitation surface**, by design.

- The `exploit` tier exists structurally but registers no modules and refuses:
  `internal/cli/cli.go:222-229` returns exit 2 with
  "exploit has no modules in this framework (assessment is offline and
  read-only)" — VERIFIED by execution.
- Safe-exploitability verification, exploit correlation, PoC execution, and
  post-exploitation are **NOT APPLICABLE** to an offline sample-analysis domain.
  The "assessment" that maps to the offensive lifecycle is the static triage
  itself.
- The exploitation-adjacent *honesty* requirement (do not fake capability) is
  satisfied: `kush.dynamic` and `kush.host.execution` are declared unimplemented
  and refused (`capabilities.go:105-107`, `safety.go`).

---

## 8. High-level implementation candidates (P0–P3)

These are feasible with the current machine/dependencies (no specialised
hardware). They are recommendations only.

- **P1 — Real static parsers for common container formats.** Today detection
  operates on a pre-parsed sample document. Feasible additions that stay offline:
  PE/ELF/Mach-O header parsing, section/entropy computation, import-table
  extraction, embedded-file carving, and Authenticode parsing — all pure
  file-reading, no execution. Evidence of gap: the model has `Sections`,
  `Imports`, `Embedded`, `Metadata` fields (`malware.go:79-114`) but nothing in
  the repo *populates* them from a real file; only `simulate.go` does
  (VERIFIED: no parser package exists under `internal/`).
- **P1 — Sandbox-observation import adapter.** A documented, read-only importer
  for behavior records produced by an *external* isolated sandbox would make
  `kush.behavior` more than a modelled field, without executing anything locally.
  Gap evidence: `detect.UnverifiedRiskItems` exists but no importer.
- **P2 — YARA-style / signature rule loading.** The registry is code-defined
  (`internal/rules/builtin/builtin.go`); a signed rule-file loader would extend
  coverage without changing the safety model. Gap: no rule-file loader found.
- **P2 — IOC export interchange formats.** STIX/CSV/MISP export from the existing
  IOC model (`malware.go:142-150`). Gap: only report formats (md/json/yaml/html)
  exist (`reporting.go`).
- **P3 — Hash computation over raw input.** `kush.hashing` is declared
  implemented but operates on hashes carried in the document; computing MD5/SHA
  directly from a raw file would strengthen it. (Marked P3 pending confirmation
  of intent — see §15.)

---

## 9. Low-level deferred technique inventory (DEFERRED — SPECIALISED PREREQUISITES)

These are relevant to a mature malware-analysis framework but require isolated
laboratory infrastructure the current environment does not provide. They are
documented, **not implemented**, and correctly deferred.

| Technique | Objective | Prerequisites | Feasibility | Current status | Deferral reason | Conditions to implement |
|---|---|---|---|---|---|---|
| Dynamic execution in a sandbox | Observe real runtime behavior | Hardware-isolated VM/sandbox (KVM/Xen, snapshots, no shared network), strict egress control | High (with infra) | MISSING, refused (`detect.go:200-202`, KSH-012) | No isolated runtime on developer host; executing unknown samples is unsafe | Provision a disposable, network-isolated sandbox with auto-revert; wire `kush.behavior` to import its observations |
| Memory forensics of a live infection | Extract injected code/artifacts | Volatility + physical memory image from an isolated VM | Medium | MISSING | Requires a controlled victim environment | Sandbox with memory acquisition hooks |
| Kernel-level / rootkit behavior tracing | Observe stealth techniques | Instrumented kernel in an isolated VM | Medium | MISSING | Same sandbox prerequisite | Hypervisor introspection support |
| Full unpacking / emulation (e.g., Unicorn/Qiling) | Defeat packers | CPU emulation dependency (new module) | Medium | MISSING | Adds a heavyweight dependency; benchmark needed | Assess emulator dependency and CPU-budget bounds |
| Detonation of weaponised documents | Document-based exploit observation | Air-gapped lab with disposable OS images | High (with infra) | MISSING | Physical/lab isolation required | Same as dynamic sandbox |

All of the above are **DEFERRED — SPECIALISED PREREQUISITES**. None is
classified as irrelevant.

---

## 10. Common-layer conformance

Reference: `shared/qyvora-common/contract/contract.go` (frameworks implement the
contract natively, do not import it) and
`shared/qyvora-common/conformance/runner.go`.

| Dimension | Classification | Evidence / rationale |
|---|---|---|
| Exit codes 0/1/2/130 | SHARED (conformant) | `internal/exitcode/exitcode.go:8-13`; VERIFIED unknown flag/command → 2, success → 0 |
| Exit code 3 (unsupported/refused) | MISSING | Contract declares `ExitUnsupported=3` (`contract.go:18-24`); kush defines only 0/1/2/130 (`exitcode.go`). Kush has no unsupported-target path today, so the gap is latent, not a defect |
| Framework identity block | SHARED (conformant) | `internal/version/version.go:GetInfo`; VERIFIED `version -o json` shape matches `contract.VersionResult` |
| Semver identity | SHARED (conformant) | `version -o json` → `v0.1.0`; conformance rule `version-semver` applicable |
| JSONL event envelope | SHARED (conformant) | `internal/events/events.go:1-9` — `schema_version/timestamp/execution_id/framework/level/event/data`; matches `contract.Envelope` |
| Capability manifest | FRAMEWORK-SPECIFIC shape | `internal/capabilities/capabilities.go:35-49` — richer than `contract.CapabilityManifest` (which only has `name/inputs/outputs/dangerous/authorization/emits/deterministic`). Kush adds `implemented`/`live`/verbs/severities |
| `--events` destination flag | SHARED (conformant) | `internal/cli/cli.go:202`; behaviour pinned by `internal/cli/events_destination_test.go` |
| Output format flag `-o` | SHARED (conformant) | `internal/cli/cli.go:199` |
| Structured result document | SHARED (conformant) | `assess -o json` returns canonical result with `findings`/`evidence`/`score`/`level` (VERIFIED) |
| Config load/validation | DUPLICATED | `internal/config/config.go` (viper) mirrors mansa's structurally; a candidate for consolidation or a shared helper |
| Typed exit errors | DUPLICATED | `internal/errors` exists; mansa has an equivalent `internal/errors` — near-identical `ExitError` semantics |
| Target model (type/value/auth) | FRAMEWORK-SPECIFIC | `internal/target/manager.go`, `pkg/models/target.go` — kush targets are offline sample/simulation; mansa targets are interfaces/BSSIDs |
| Capability discovery for orchestrator | SHARED (conformant) | `capabilities -o json` is machine-readable and honest about the unimplemented `kush.dynamic` |
| TUI retirement `//go:build ignore` | SHARED convention | `internal/cli/tui.go:1` — same fleet-wide pattern as mansa |

**Key finding.** Kush's event envelope, identity, exit codes and `-o`/`--events`
flags align with the documented common contract. The only concrete divergence is
the absent exit code `3`, which is latent because kush has no "understood but
unsupported" path.

---

## 11. AI orchestration readiness

Assessment against PROMPT.md §9 requirements. Statuses:
CONFORMANT / PARTIALLY CONFORMANT / NONCONFORMANT / NOT APPLICABLE / UNVERIFIED.

| Requirement | Status | Evidence |
|---|---|---|
| Stable discoverable identity | CONFORMANT | `version -o json` → `"framework":"kush"` (VERIFIED) |
| Version/compatibility metadata | CONFORMANT | `version.go:GetInfo` full build identity |
| Machine-readable capability description | CONFORMANT | `capabilities -o json`, 10 records with `implemented`/`live` (VERIFIED) |
| Explicit operation inputs/outputs | PARTIALLY CONFORMANT | Command records carry `output_modes`/`sim_support` (`capabilities.go:29-33`) but no per-command input schema (unlike mansa's `Schema`) |
| Predictable exit codes and errors | CONFORMANT | 0/1/2/130 (`exitcode.go`); VERIFIED |
| Structured results and evidence | CONFORMANT | `assess -o json` canonical result (VERIFIED); `internal/evidence` |
| Clear prerequisite declarations | PARTIALLY CONFORMANT | Preflight in `validation.go`; no capability-level prerequisite field in the manifest |
| Permission/authorization requirements | CONFORMANT | `authorization_model` string in manifest (`capabilities.go:88-92`); offline needs none |
| Timeouts and cancellation | CONFORMANT | `signal.NotifyContext` (`internal/cli/cli.go:103`); pipeline checks `ctx.Err()` (`pipeline.go:73-75`) |
| Resource/concurrency constraints | PARTIALLY CONFORMANT | Input size bound (`malware.go:175`); no formal resource declaration in the manifest |
| Safe execution defaults | CONFORMANT | Read-only offline; `kush.dynamic` refused |
| Read-only vs state-changing distinction | CONFORMANT | `safety.go` `ChangesState`/`Reversible`; all shipped ops read-only |
| Risk classification / confirmation | CONFORMANT | `safety.go` `OperationMetadata` (risk/noise/confirm) |
| Consistent logging / correlation | CONFORMANT | `execution_id` in every event (`events.go`) |
| Compatibility with common contracts | PARTIALLY CONFORMANT | See §10 — exit code 3 absent; capability manifest superset |
| Honest unsupported reporting | CONFORMANT | `implemented:false` for `kush.dynamic`; `sources` marks `live` unimplemented |

**Orchestration verdict: CONFORMANT (with minor gaps).** A future orchestrator
can discover kush, read its capabilities, invoke it with `-o json`/`--events`,
and interpret results through the canonical result document and exit codes. The
chief orchestration soft spot is the lack of a per-command input schema in the
capability manifest.

**Recommended future contract (not implemented):** add an
`inputs`/`parameters` array per command mirroring mansa's `Schema{Input,Output}`,
and declare exit code 3 for unsupported targets, so one orchestrator parser
covers both frameworks.

---

## 12. CLI, repository-layout, and documentation findings

### Layout (exact paths; nothing moved or deleted)

- **Binary placement — CORRECT:** `bin/kush` (`bin/`, 9.2 MB). `bin/` is
  gitignored (`.gitignore:2`) with `bin/.gitkeep` tracked. No compiled binary in
  the repo root. **No stray root executable found.**
- **Assets — CORRECT:** `assets/kush.desktop`, `assets/kush.ico`,
  `assets/kush.png` all under `assets/`.
- **`continue_AI.sh` — NOT PRESENT.** PROMPT context noted a possible
  `continue_AI.sh` at root. VERIFIED: no such file exists; `.gitignore:6` lists
  `continue_AI.sh` and `git ls-files` does not track it. So the "stray script"
  is either already removed or a different checkout state. **No action needed.**
- **Docs** — `docs/` contains **20 zero-byte placeholder files** plus two real
  files (`docs/CLI.md` 1,045 B, `docs/README.md` 2,325 B). The placeholders are
  acknowledged honestly by `docs/README.md`. See §14.
- **`docs/CLI.md` accuracy — STALE (P2):** it says "recon: _No recon-tier
  modules._" and "report: _No report-tier modules._", but `kush recon` in fact
  registers assess/sample/sources/rules/target and `kush report` registers
  findings/evidence (`internal/cli/cli.go:214-220,249`) — VERIFIED via
  `kush recon --help`. It also lists a `kush tui` command in the utilities table
  (`docs/CLI.md`) even though the TUI is `//go:build ignore` and not wired
  (`internal/cli/tui.go:1`, PROMPT: "retire per-tool TUI"). CLI.md also writes
  `docs script` instead of `kush script`.
- **`reports/` — untracked runtime output.** Contains `evidence.json`,
  `result.json`, and 4 generated markdown reports (VERIFIED present). Only
  `reports/.gitkeep` is tracked; `reports/` is gitignored (`.gitignore:7`).
  These are legitimate runtime artifacts, not committed clutter.
- **Empty placeholder markdown at root:** `CHANGELOG.md`, `CODE_OF_CONDUCT.md`,
  `CONTRIBUTING.md`, `GOVERNANCE.md`, `SUPPORT.md` are zero bytes
  (VERIFIED). `LICENSE` (1,070 B) and `NOTICE` (1,050 B) are **non-empty** —
  the README's blanket claim that these are zero-byte is itself **stale**.
- **CI:** `.github/workflows/ci.yml`, `release.yml` present.
- **Duplicate scripts:** `scripts/build.sh`, `install.sh`, `release.sh`,
  `test.sh`, `verify-artifact.sh` coexist with root `Makefile` targets
  (`build/test/vet/lint/verify/install`). Mild duplication; not harmful.

### CLI

- Canonical tier grammar plus hidden legacy aliases
  (`internal/cli/cli.go:262-272`) — good backward compatibility.
- Global flags: `-o`, `-q`, `--no-color`, `--events`, `--allow-shellout`
  (`cli.go:198-203`).
- `exploit` tier refuses with a meaningful message and exit 2 (VERIFIED).

---

## 13. Testing and verification findings

**Only checks actually run are reported.**

- `go test ./... -count=1 -timeout 180s` → **PASS** (exit 0). Packages with
  tests: `internal/analysis`, `banner`, `cli`, `config`, `events`, `evidence`,
  `malware`, `output`, `pipeline`, `risk`, `rules`, `rules/builtin`,
  `selfupdate`, `target`, `validation`, `pkg/models`. Packages **without** test
  files: `cmd/kush`, `capabilities`, `errors`, `exitcode`, `reporting`,
  `safety`, `version`. VERIFIED from the run output.
- `go vet ./...` → **PASS** (exit 0, no findings).
- `bin/kush version -o json` → exit 0, valid JSON.
- `bin/kush capabilities -o json` → exit 0, 10 capability records.
- `bin/kush nosuchcmd` → exit 2; `bin/kush --nosuchflag` → exit 2.
- `bin/kush exploit` → exit 2, honest refusal message.
- `bin/kush assess --sim -o json --events off --no-report` → exit 0, result
  document with 16 findings, `score`/`level` present.

**Not run (recorded as UNVERIFIED with reason):**

- `make lint` / `golangci-lint` — not run to avoid regenerating or altering
  tooling state; `go vet` was used as a safe substitute.
- Interrupt (SIGINT → 130) path — not exercised to avoid terminating a session
  mid-run; code path confirmed by reading `internal/cli/cli.go:103` and
  `exitcode.Interrupted`. **UNVERIFIED at runtime.**
- Race detector (`make test-race`) — not run.

**Coverage observations (INFERRED from file listing):** the core domain
(`malware`, `detect`, `rules`, `risk`, `pipeline`, `evidence`) is well tested;
the orchestration-facing shells (`exitcode`, `version`, `safety`, `reporting`)
lack direct tests.

---

## 14. Prioritized gaps and recommendations

| # | Priority | Gap | Why it matters | Recommended later action |
|---|---|---|---|---|
| G1 | **P1** | No raw-file parsers; analysis depends on a pre-parsed sample document | Limits real-world triage usefulness | Add offline PE/ELF/Mach-O parsers populating the existing model fields |
| G2 | **P1** | Capability manifest lacks per-command input schema | Orchestrator must special-case kush | Add `inputs`/`outputs` per command |
| G3 | **P1** | Behavioral analysis has no sandbox-observation importer | `kush.behavior` is only as rich as the input document | Add a read-only importer from an external isolated sandbox |
| G4 | **P2** | `docs/CLI.md` is stale (module tiers, `tui`, `docs script`) | Misleads users and orchestrators | Regenerate from the live command tree |
| G5 | **P2** | 20 zero-byte `docs/` placeholders + 5 zero-byte root docs; README claims LICENSE/NOTICE empty when they are not | Documentation trust | Populate or remove placeholders; correct README |
| G6 | **P2** | No exit code 3 for unsupported targets | Contract divergence | Add refused/unsupported mapping when such paths appear |
| G7 | **P2** | `internal/errors`, `internal/config`, `internal/exitcode` duplicate mansa's | Maintenance drift | Consider a shared common-layer helper |
| G8 | **P3** | No rule-file (YARA-style) loading | Extensibility | Add signed rule-file loader |
| G9 | **P3** | IOC interchange export (STIX/MISP/CSV) absent | Threat-intel integration | Add exporters over the existing IOC model |
| G10 | **P3** | `scripts/*.sh` duplicate Makefile targets | Minor confusion | Consolidate |

---

## 15. Dependencies, prerequisites, unresolved questions

**Build/runtime dependencies (VERIFIED from `go.mod`):** Go 1.26.5 toolchain
(binary reports go1.27.1), `spf13/cobra`, `spf13/viper`, `fatih/color`,
`muesli/termenv`, `go.yaml.in/yaml/v3`, and shared `QYVORA/qyvora-script`
v0.1.0 and `QYVORA/qyvora-tui` v0.11.0. No network libraries; no execution
sandbox; no external binaries required.

**Prerequisites:** none for offline analysis. A sandbox is required only for the
deferred dynamic-execution techniques (§9).

**Unresolved questions:**

1. Does `kush.hashing` intend to *compute* digests from raw files, or only carry
   declared hashes? The contract marks it implemented and `Live:false`
   (`capabilities.go:84`), but no hashing over raw bytes was found. **UNVERIFIED.**
2. Is `kush.behavior` (`Live:true`) intended to be fed by a future sandbox, or is
   the "live" flag aspirational? `README.md:23-24` says `KSH-011` grades sandbox
   observations; no connector ships. **INFERRED: future work.**
3. `docs/README.md` claims `LICENSE`/`NOTICE` are zero-byte; both are non-empty
   (1,070/1,050 B). Which is authoritative? **Documentation inconsistency.**
4. The PROMPT context referenced `continue_AI.sh` at root; it is absent and
   gitignored. Confirm whether the audit target expectation predates a cleanup.

---

## 16. No feature implementation was performed during this audit.

No feature was implemented, no command was added, no rule was added, no
refactoring occurred, no dependency was introduced, no configuration changed,
and no existing file was modified. The **only** file created by this audit is
`AUDIT.md`. The working tree was clean at audit start and remains clean apart
from this deliverable. All tests and probes were non-destructive and read-only;
no sample was executed and no network I/O was performed.
