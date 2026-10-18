# CLI Reference

`kush` follows the shared QYVORA tier grammar:

```
kush <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

_No recon-tier modules._

## exploit

_No exploit-tier modules._

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `kush assess` | run the analysis pipeline against a sample or simulation |
| `kush evidence` | inspect the latest assessment evidence |
| `kush findings` | inspect the latest assessment findings |
| `kush rules` | list the registered analysis rules |
| `kush sample` | generate a deterministic sample malware document |
| `kush sources` | list supported sample sources and their status |
| `kush target` | manage assessment targets (sample documents and simulation) |
| `kush tui` | start the interactive terminal application |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |
