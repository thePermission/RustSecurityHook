# ADR 010: Criterion Benchmarks for the run_check Pipeline

## Context

`rsh` is invoked on every Bash, Write, and Edit tool call. Performance regressions in
`run_check` are invisible without a measurement baseline. After the BinGroup fast-path
(ADR 001) improved hot-path latency, a repeatable benchmark suite became necessary to
detect regressions in future changes.

Benchmark files in `benches/` compile as a separate crate and can only access items
from a `[lib]` target, not a `[[bin]]` target. The original code had all logic in
`src/main.rs`, which is a `[[bin]]` crate — unreachable from `benches/`.

## Decision

### Library crate (`src/lib.rs`)

Extract `run_check`, `run_check_content`, `is_protected_path`, and all helper functions
from `src/main.rs` into a new `src/lib.rs`. The four submodules (`aliases`, `blacklist`,
`disabled`, `forbid`) are declared in `lib.rs` and re-imported in `main.rs` via
`use rsh::...`. `src/main.rs` becomes a thin CLI dispatcher only.

### Benchmark crate (`benches/hook.rs`)

Four benchmark groups using Criterion 0.5 with `html_reports`:

| Group | Commands | Expected result |
|---|---|---|
| `harmless` | `ls -la`, `git status`, `cargo build --release`, `echo hello`, `cat /tmp/file` | exit 0 |
| `blocked_k8s` | `kubectl delete ns production`, `kubectl delete --all -n default`, `kubectl delete crd mykind` | exit 2 |
| `blocked_helm` | `helm uninstall my-release`, `helm rollback my-release 0` | exit 2 |
| `edge` | empty string, 10 000-character string of repeated `x` | exit 0 |

Each group runs every command through `run_check` once per Criterion sample iteration
using `criterion::black_box` to prevent dead-code elimination.

## Alternatives considered

- **`cargo bench` with `#[bench]`**: nightly-only, no statistical analysis, harder to
  compare across runs.
- **Inline microbenchmarks in unit tests**: no HTML reports, no regression tracking,
  harder to isolate.

## Consequences

- `cargo bench` produces timing and statistical data for the full `run_check` pipeline.
  Criterion saves baselines in `target/criterion/` and prints change percentages on
  subsequent runs.
- The CLAUDE.md benchmark workflow section documents when to capture before/after
  snapshots and how to record results in commit messages or ADRs.
- `blocked_k8s` and `blocked_helm` groups print `rsh blocked ...` to stderr on every
  iteration — suppress with `cargo bench 2>/dev/null` for clean output.
- JSON deserialization (stdin parsing) is excluded from benchmarks: it is a one-time
  ~1 µs cost that does not scale with rule count and is not worth optimising.
