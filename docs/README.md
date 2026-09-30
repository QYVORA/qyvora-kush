# KUSH — Documentation Index

**Status:** `CURRENT` (this index) · **Last reviewed:** 2026-09-30

KUSH is offline malware sample analysis.

## Pipeline and rules

```
INTAKE → HASH → METADATA → STATIC → STRINGS → BEHAVIOR → NETWORK → IOC → RISK
```

Rules: KSH-001…KSH-014.

## Safety boundary

`kush.dynamic` is disabled by default and the corresponding safety
operation is refused — `kush.host.execution` is refused. Secrets are redacted in output.

## What is actually written

**Authoritative for this tool, and currently non-empty:**

- `../README.md` — purpose, install, quick start, CLI, capabilities, safety

Cross-project contracts (authoritative, non-empty):

- [QYVORA-ECOSYSTEM.md](../../../../knowledge/qyvora-docs/09-technical/cross-project/QYVORA-ECOSYSTEM.md)
- [QYVORA-TOOL-OUTPUT-SPEC.md](../../../../knowledge/qyvora-docs/09-technical/cross-project/QYVORA-TOOL-OUTPUT-SPEC.md)
- [07-products overview](../../../../knowledge/qyvora-docs/07-products/kush/)

## Known gap — placeholder files (`UNVERIFIED`)

**27 Markdown files in this repository are zero-byte placeholders.**
They are tracked in git but contain no content, so they must not be
cited as documentation. This file is the honest index; the placeholders
are left in place rather than filled with placeholder prose, and are
tracked for completion.

Repository root:

- `CHANGELOG.md`
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- `GOVERNANCE.md`
- `SECURITY.md`
- `SUPPORT.md`

`docs/` (21 placeholders):

- `docs/Architecture.md`
- `docs/Behavior-Analysis.md`
- `docs/CLI.md`
- `docs/Configuration.md`
- `docs/Console.md`
- `docs/Development.md`
- `docs/Evidence.md`
- `docs/Getting-Started.md`
- `docs/IOC-Extraction.md`
- `docs/Installation.md`
- `docs/Metadata.md`
- `docs/Network-Indicators.md`
- `docs/Reporting.md`
- `docs/Roadmap.md`
- `docs/Sample-Intake.md`
- `docs/Security-Model.md`
- `docs/Static-Analysis.md`
- `docs/Strings.md`
- `docs/Targets.md`
- `docs/Threat-Classification.md`
- `docs/Validation.md`

Related root files that are **also** zero-byte: `LICENSE`, `NOTICE`.
Until they are populated, this tool's license is `UNVERIFIED` even
though its README shows a license badge. See
[`00-audit/LEGAL_REVIEW_REGISTER.md`](../../../../knowledge/qyvora-docs/00-audit/LEGAL_REVIEW_REGISTER.md).
