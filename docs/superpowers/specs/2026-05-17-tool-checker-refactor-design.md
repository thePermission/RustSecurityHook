# Design: Tool-Checker Refactor

**Date:** 2026-05-17  
**Status:** Approved

## Context

Currently `run_check` calls `blacklist::check` and `forbid::check` sequentially against the
entire command string, then reads any script files found in the command and checks their content
the same way. This means all rules are always evaluated regardless of which tools appear in the
command, and scripts are checked sequentially after the direct command check.

## Goal

Restructure the check pipeline so that:

1. Commands are split into segments (direct tool calls vs. script executions).
2. Each segment is checked only by the rules relevant to the tools it contains.
3. Per-tool checks run in parallel with fail-fast behaviour.
4. The `ToolChecker` abstraction is the single entry point for all checks — both for script
   content and for direct command strings.

## Architecture

### New module: `src/checker.rs`

Contains the `ToolChecker` trait, all concrete implementations, tool detection, segment
classification, and the parallel execution driver.

```rust
pub trait ToolChecker: Send + Sync {
    fn bins(&self) -> Vec<String>;
    fn check(&self, content: &str) -> Option<Hit>;
}

pub struct KubectlChecker;  // kubectl blacklist rules + forbid (cluster/namespace)
pub struct HelmChecker;     // helm blacklist rules

pub struct Hit {
    pub rule_id: String,
    pub reason:  String,
}
```

Adding support for a new tool (e.g. `docker`) means adding one struct that implements
`ToolChecker` and registering it in `detect_checkers`.

### Segment classification

```rust
pub enum Segment {
    Script { path: String },
    Direct { command: String },
}

pub fn split_segments(command: &str) -> Vec<Segment>
```

Replaces the existing `script_paths_in` function. For each shell fragment (split by `;`, `&&`,
`||`, `|`, `\n`) the function decides:

- If the fragment invokes a known interpreter (`bash`, `sh`, `python`, …) with a file argument,
  or executes a path directly (`./foo.sh`, `/usr/local/bin/script`): `Segment::Script`.
- Otherwise: `Segment::Direct`.

### Tool detection

```rust
pub fn detect_checkers(content: &str) -> Vec<Box<dyn ToolChecker>>
```

Scans `content` for the binary names and aliases of each known tool. Returns only the checkers
whose tool appears in the content. An empty result means no rules apply — the segment passes.

`KubectlChecker` always includes the `forbid` check (cluster and namespace) in addition to the
blacklist rules, because `forbid::check` is specifically tied to kubectl/helm context.

### Parallel execution

All checker threads for all segments of a single command share one `Arc<AtomicBool>` stop flag
and one `mpsc::channel`:

```
for segment in split_segments(command):
    content = read_file(path) | command_string
    for checker in detect_checkers(content):
        spawn thread → checker.check(content)
                     → on hit: set stop flag, send Hit to channel

main thread: rx.recv() → Some(hit) → exit 2
                       → None (channel closed) → exit 0
```

Each thread checks the stop flag before starting work. The first thread to find a hit sets the
flag, sends the hit, and exits. Other threads observe the flag and exit without work.
Script files that cannot be read are silently skipped (fail-open).

## Changes by file

| File | Change |
|---|---|
| `src/checker.rs` | New: trait, `KubectlChecker`, `HelmChecker`, `detect_checkers`, `split_segments`, parallel driver |
| `src/lib.rs` | `run_check` rewritten to use `checker`; `script_paths_in` / `extract_script_path` removed |
| `src/lib.rs` | `run_check_content` rewritten to use `detect_checkers` |
| `src/blacklist.rs` | Unchanged — called internally by checkers |
| `src/forbid.rs` | Unchanged — called internally by `KubectlChecker` |
| `src/main.rs` | Unchanged |

No new dependencies are required.

## Error handling and exit-code contract

- Thread panic → channel drop → `rx.recv()` returns `Err` → treated as no hit (fail-open).
- Unreadable script file → silent skip.
- No tool recognised in a segment → no thread spawned → segment passes.
- Only exit codes `0` (allow) and `2` (block with reason on stderr) are produced.

## Testing

`src/checker.rs` gets its own unit-test module covering:

- `KubectlChecker` blocks known-bad commands.
- `HelmChecker` blocks known-bad commands.
- `detect_checkers` returns only the relevant checkers for a given content string.
- `split_segments` correctly classifies script and direct segments.
- Mixed commands (`kubectl apply … && ./deploy.sh`) produce one `Direct` and one `Script` segment.
- Parallel execution returns the first hit and exits 2.

Existing tests in `blacklist.rs`, `forbid.rs`, and `lib.rs` remain unchanged.
