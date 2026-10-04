# Kush

> **Offline malware sample analysis framework.**
> A terminal-first console and CLI for static sample analysis: hashes,
> metadata, static posture, strings, network indicators, IOC extraction
> and threat classification — without ever executing the sample.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Kush is QYVORA's offline malware sample analysis framework. It runs as a
shared terminal-first console **and** a one-shot CLI with identical
commands, and produces evidence-backed findings with transparent risk
scoring. **Samples are never executed on the developer host**: dynamic
execution is not implemented and is refused honestly; behavioral findings
may only come from an isolated sandbox you attach explicitly.

- **One workflow, two surfaces** — the console commands equal the CLI
  commands.
- **Deterministic `--sim`** — fixed dataset exercises every rule, no
  executing anything, CI-ready.
- **Never executes** — static read-only analysis on your host; `KSH-012`
  records the dynamic-execution refusal honestly.
- **Verified IOC catalog** — `KSH-010` claims only IOCs corroborated
  across the sample's surfaces.
- **Status** — shipped at v0.1.0 (Go 1.26+, MIT).

## Installation

```sh
git clone https://github.com/QYVORA/qyvora-kush.git
cd qyvora-kush
make build
sudo make install          # /usr/local layout (root)
make install-user          # ~/.local layout (no root)
```

Or build the single static binary directly with the Go toolchain:

```sh
go build ./cmd/kush
```

No release assets are published yet; `kush updates` installs release
builds once the first verifiable release exists.

## Quickstart

Full assessment, no input required, deterministic:

```sh
kush assess --sim       # risk 100/100 (critical)
```

Generate a sample malware document and assess it:

```sh
kush sample --sim
kush assess sample.sim.json
```

Interactive console (REPL on a real terminal; stdin piping uses a plain line reader):

```sh
kush
assess --sim
findings
evidence
exit
```

Machine-readable output:

```sh
kush capabilities -o json
kush assess -o json
kush report -o json
```

## Commands

```
assess        run the analysis pipeline against a sample or simulation
capabilities  print the machine-readable capability contract
console       start the interactive assessment console
evidence      inspect the latest assessment evidence
findings      inspect the latest assessment findings
report        render the latest assessment report from disk
rules         list the registered analysis rules
sample        generate a deterministic sample malware document
sources       list supported sample sources and their status
target        manage assessment targets (sample documents and simulation)
updates       check for and install verified releases
version       print version and build metadata
```

Global flags: `-o/--output`, `-q/--quiet`, `--no-color`.

## Analysis rules

```
KSH-001  Suspicious process-spawning imports                 high
KSH-002  Packed or high-entropy binary                      medium
KSH-003  Unsigned binary with no publisher                  medium
KSH-004  Persistent autostart mechanism                       high
KSH-005  Command-and-control indicators                    critical
KSH-006  Encoded command launcher                             high
KSH-007  Embedded staged payload                            medium
KSH-008  Browser user-agent impersonation                   medium
KSH-009  Socket imports with process access                 medium
KSH-010  Verified high-confidence IOC catalog         informational
KSH-011  Behavioral anomalies from sandbox                    high
KSH-012  Dynamic execution on developer host refused          low
KSH-013  Process injection primitives                         high
KSH-014  Writable-and-executable section                    medium
```

## Capabilities

`kush capabilities` prints the machine-readable contract. The
deliberate boundary: `kush.dynamic` (dynamic execution) is **refused on
the developer host** and requires a strongly isolated sandbox — samples
are never executed.

## Documentation

- **[`docs/README.md`](docs/README.md) — the documentation index.** It lists what is
  actually written, and names every zero-byte placeholder file explicitly so
  nothing empty is cited as documentation.
- Pipeline stages, analysis rules and risk scoring: the tool's own
  `capabilities` output, `docs/README.md`, and the QYVORA product overview.
- Cross-project contracts: the QYVORA tool output spec and ecosystem doc.

> **Documentation gap.** This repository still has zero-byte placeholder
> files (including `LICENSE` and `NOTICE`). `docs/README.md` names them all.

## Support

See [SUPPORT.md](SUPPORT.md). Report issues on GitHub.

## About QYVORA

**QYVORA is an African cybersecurity company — built in Tamale, Ghana, serving the
whole continent.** Its mission is to build Africa's strongest cybersecurity
ecosystem and develop the talent to run it.

Kush is part of a fourteen-framework open-source offensive security toolkit. The
frameworks are unrestricted free software, published for defenders and researchers
across Africa and beyond.

- Company and services: https://qyvora.org
- All frameworks: https://github.com/QYVORA

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Analyze sample documents you are authorized to
evaluate; nothing is executed on your host and nothing is uploaded.