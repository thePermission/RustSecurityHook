# ADR 011: ToolChecker Trait and Parallel Check Pipeline

## Context

`rsh` previously ran checks sequentially: `blacklist::check` on the full command string,
then `forbid::check` on the same string, then `script_paths_in` to extract any referenced
script files, and finally the same two checks repeated on each script's content. All rules
were evaluated regardless of which tools appeared in the command.

Two problems followed from this design:

1. **No tool isolation** — every rule ran against every command. Adding a new tool's rules
   meant they were evaluated even for commands that didn't invoke that tool.
2. **No parallelism** — script files were read and checked sequentially, and the blacklist
   and forbid pipelines could not overlap.

## Decision

Introduce a `ToolChecker` trait in `src/checker.rs` and restructure `run_check` around it.

### `ToolChecker` trait

```rust
pub trait ToolChecker: Send + Sync {
    fn bins(&self) -> Vec<String>;
    fn check(&self, content: &str) -> Option<Hit>;
}
```

Each concrete implementation encapsulates the rules for one tool family:

| Struct | Covers | Includes forbid? |
|---|---|---|
| `KubectlChecker` | `kubectl` and its aliases | Yes — cluster + namespace |
| `HelmChecker` | `helm` and its aliases | Yes — cluster + namespace |
| `DockerChecker` | `docker`, `docker-compose` and aliases | No |
| `RshChecker` | `rsh` self-protection rules | No |
| `FallbackChecker` | `bin=None` rules (SQL, subprocess bypass, rsh config protection) + `forbid::check_db` | Always included |

`FallbackChecker` returns an empty `bins()` slice and is always included by `detect_checkers`,
so rules that are not tied to a specific binary continue to run on every segment.

### Segment classification

```rust
pub enum Segment {
    Script { path: String },
    Direct { command: String },
}

pub fn split_segments(command: &str) -> Vec<Segment>
```

`split_segments` replaces the old `script_paths_in` + `extract_script_path` helpers. It
splits the command on shell separators (`;`, `&&`, `||`, `|`, `\n`) and classifies each
fragment: if the fragment invokes a known interpreter (`bash`, `sh`, `python`, …) with a
file argument, or executes a path directly (`./foo.sh`, `/usr/local/bin/script`), it becomes
`Segment::Script`; otherwise `Segment::Direct`.

### Parallel execution

```rust
pub fn run_parallel_checks(segments: Vec<Segment>) -> Option<Hit>
```

All checker threads for all segments share one `Arc<AtomicBool>` stop flag and one
`mpsc::channel`. For each segment, `detect_checkers` scans the content and returns only the
checkers whose tool appears in it. One thread is spawned per checker. The first thread to
find a hit sets the stop flag and sends the hit. All other threads observe the flag on entry
and exit without work. `drop(tx)` after spawning ensures `rx.recv()` returns `None` when no
hits are found.

Script files that cannot be read are silently skipped (fail-open). Thread panics are
absorbed by the channel close — `rx.recv()` returns `Err`, treated as no hit (fail-open).

### `blacklist::check_for_bin`

A new `check_for_bin(content, bin: Option<&str>)` function was added alongside the existing
`check`. It filters rules by the `bin` field, allowing checkers to run only the rules
relevant to their tool without touching the BinGroup fast-path used by the old `check`.

## Alternatives considered

- **rayon** — data-parallel iterator library. Would simplify the fan-out but adds a
  dependency and introduces a global thread pool, making fail-fast harder to implement
  cleanly.
- **tokio / async-std** — async runtime. Appropriate for I/O-bound work; for CPU-bound regex
  matching with a small number of checkers, the overhead of a full async runtime is not
  justified.
- **Sequential per-tool checks** — same tool isolation without parallelism. Simpler, but
  misses the latency benefit for commands that invoke multiple tools or reference slow-to-read
  script files.

## Consequences

- **Adding a new tool** means adding one struct that implements `ToolChecker` and one entry
  in the `detect_checkers` candidates list — no changes to `run_check` or `lib.rs`.
- **`src/lib.rs`** is now ~67 lines. `run_check` and `run_check_content` both delegate to
  `checker::split_segments` + `checker::run_parallel_checks`. The old `script_paths_in`,
  `extract_script_path`, and `strip_quotes` helpers are gone.
- **`src/blacklist.rs`** gains `check_for_bin` but is otherwise unchanged.
- **`src/forbid.rs`** is unchanged. Checkers call `forbid::check_with` (for kubectl/helm)
  or `forbid::check_db` (for the fallback) directly.
- **`src/main.rs`** is unchanged.
- **Exit-code contract** (0 = allow, 2 = block) is preserved.
- **No new dependencies** are required.
