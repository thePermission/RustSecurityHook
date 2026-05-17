# Performance Benchmarks Design

**Date:** 2026-05-17  
**Status:** Approved

## Goal

Measure how long `rsh` takes to evaluate a command in hook mode. The target is the
full internal check pipeline — blacklist regex matching, forbid list lookup, and script
detection — without process-startup overhead.

## Scope

The benchmark covers `run_check(command: &str) -> ExitCode`, which is the canonical
entry point shared by hook mode and `rsh check`. It exercises:

1. `blacklist::check` — regex matching against all compiled rules
2. `forbid::check` — cluster/namespace lookup (falls through if no entries are configured)
3. `script_paths_in` + file reads — script execution detection

JSON deserialization (stdin parsing) is excluded; it is a one-time ~1 µs cost that does
not scale with rule count and is not interesting to optimise.

## Framework

[Criterion.rs](https://github.com/bheisler/criterion.rs) v0.5 with HTML reports.

- Statistical analysis (mean, std dev, confidence intervals)
- Regression detection across runs via saved baselines in `target/criterion/`
- No nightly toolchain required

## Changes

### `Cargo.toml`

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "hook"
harness = false
```

### `src/main.rs`

`run_check` changes from `fn` to `pub(crate) fn` so `benches/hook.rs` can call it
directly. No other visibility changes.

### `benches/hook.rs`

Four benchmark groups, each using `criterion::black_box` to prevent dead-code
elimination:

| Group | Commands | Expected exit |
|---|---|---|
| `harmless` | `ls -la`, `git status`, `cargo build --release`, `echo hello`, `cat /tmp/file` | 0 (pass) |
| `blocked_k8s` | `kubectl delete ns production`, `kubectl delete --all -n default`, `kubectl delete crd mykind` | 2 (block) |
| `blocked_helm` | `helm uninstall my-release`, `helm rollback my-release 0` | 2 (block) |
| `edge` | `""` (empty string), 10 000-character string of repeated `x` | 0 (pass) |

Each group runs every command through `run_check` once per Criterion sample iteration.

## Running

```bash
cargo bench                          # all groups
cargo bench --bench hook harmless    # single group
# HTML report: target/criterion/report/index.html
```

## Non-Goals

- Subprocess / binary-level E2E benchmarks (process startup dominates, not useful)
- Benchmarking `forbid::check` with live `kubectl` calls (non-deterministic, network)
- CI enforcement of latency thresholds (baseline comparison is a local developer tool)
