# ADR 015: Replace Thread-Per-Checker with Sequential Execution

## Context

ADR 011 introduced a parallel execution model: for each segment, one `std::thread` was spawned per selected checker. A shared `Arc<AtomicBool>` stop flag and `mpsc::channel` coordinated early exit on the first hit.

Benchmark analysis (Criterion, rsh v0.8.1) showed that `std::thread::spawn` costs ~10–20 µs on Linux. Since `FallbackChecker` and `SecretFileChecker` both return empty `bins()` and are always included, every hook invocation — including entirely harmless commands — spawned at least two threads. The thread overhead dominated hook latency for the common case:

| Benchmark | before (threads) | after (sequential) |
|---|---|---|
| `edge/empty` | 187 ns | 47.6 ns |
| `harmless/ls -la` | 29.2 µs | 3.7 µs |
| `harmless/git status` | 37.4 µs | 10.0 µs |
| `blocked_k8s` (avg) | 44.6 µs | 24.3 µs |
| `blocked_helm` (avg) | 49.3 µs | 24.0 µs |

The original motivation for parallelism was latency reduction when multiple checkers run against long scripts. In practice, each checker is a CPU-bound regex match that completes in single-digit microseconds — far below the thread-spawn cost. The fail-fast stop flag also meant that in the common "no hit" case all threads had to run to completion anyway, providing no early-exit benefit.

## Decision

Replace the `thread::spawn` loop in `run_parallel_checks` with a sequential `for` loop over the checkers returned by `detect_checkers`. Return the first `Hit` found and stop. Remove `Arc`, `AtomicBool`, `Ordering`, `mpsc`, and `thread` imports from `src/checker.rs`.

The function name `run_parallel_checks` is kept unchanged to avoid churn in call sites and tests.

## Alternatives considered

- **Rayon `par_iter`** — eliminates cold thread-spawn cost via a reusable pool, but adds a dependency and introduces a global thread pool with its own overhead for short-lived tasks.
- **Keep threads, use a thread pool** — would reduce spawn cost but adds complexity for no measurable benefit given the sub-microsecond regex runtime per checker.
- **Keep the parallel model as-is** — does not address the measured regression for the dominant harmless-command case.

## Consequences

- `run_parallel_checks` is now ~10 lines with no synchronization primitives.
- Checker order matters for which hit is returned when multiple checkers match the same segment. The order is fixed by `detect_checkers` (Fallback → Secret → Kubectl → Helm → Docker → Rsh) and is deterministic.
- Any future checker whose `check()` is genuinely slow (e.g., network I/O) would need explicit parallelism added back at that point. For pure CPU regex work, sequential is the right default.
- ADR 011's `ToolChecker` trait, segment classification, and `detect_checkers` filter are unchanged.
