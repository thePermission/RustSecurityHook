# ADR 002 — Docker Blacklist Rules

**Date:** 2026-05-17  
**Status:** Accepted

## Context

`rsh` blocked destructive Kubernetes, Helm, and SQL operations but had no Docker coverage. Docker commands can cause irreversible data loss (volume removal), bulk container/image deletion, and are commonly issued in AI-agent sessions that manage containerized workloads. Both the modern plugin form (`docker compose`) and the legacy binary (`docker-compose`) are in common use.

Two risk tiers were identified:

- **Volume Destruction** — operations that delete volume data (irreversible without a backup).
- **Container/Image Cleanup** — operations that remove containers or images (lower severity, but bulk/destructive enough to warrant blocking in an automated context).

## Decision

Fifteen rules were added to `RAW_RULES` in `src/blacklist.rs` across two new categories.

### Docker — Volume Destruction (8 rules)

| ID | Blocked command | Reason |
|---|---|---|
| `docker-volume-rm` | `docker volume rm` / `volume remove` | Removes named volumes — irreversible data loss |
| `docker-volume-prune` | `docker volume prune` | Removes all unused volumes — bulk irreversible data loss |
| `docker-system-prune-risky` | `docker system prune` + `--volumes`/`-a`/`--all` | Deletes volumes and all images — high blast radius |
| `docker-rm-volumes` | `docker rm -v` / `--volumes` | Removes container and its anonymous volumes |
| `compose-down-volumes` | `docker compose down -v` / `--volumes` | Removes all service containers and their volumes |
| `compose-legacy-down-volumes` | `docker-compose down -v` / `--volumes` | Same via legacy CLI |
| `compose-rm-volumes` | `docker compose rm -v` / `--volumes` | Removes stopped service containers and anonymous volumes |
| `compose-legacy-rm-volumes` | `docker-compose rm -v` / `--volumes` | Same via legacy CLI |

`docker system prune` without risky flags (`--volumes`, `-a`, `--all`) is not blocked — the blast radius is lower (only stopped containers, dangling images, and unused networks).

### Docker — Container/Image Cleanup (7 rules)

| ID | Blocked command | Reason |
|---|---|---|
| `docker-container-prune` | `docker container prune` | Removes all stopped containers in bulk |
| `docker-image-prune` | `docker image prune` | Removes dangling or all unused images |
| `docker-image-rm` | `docker image rm` / `image remove` | Removes images by name or ID |
| `docker-rmi` | `docker rmi <image>` | Removes images (legacy command) |
| `docker-rm` | `docker rm <container>` | Removes one or more containers |
| `compose-down` | `docker compose down` | Stops and removes all service containers |
| `compose-legacy-down` | `docker-compose down` | Same via legacy CLI |

### Implementation notes

- All `docker` rules use `bin = Some("docker")` so registered aliases (e.g. `d → docker`) are expanded automatically.
- `docker-compose` rules use `bin = Some("docker-compose")`.
- Volume Destruction rules are ordered before Container/Image Cleanup rules in `RAW_RULES` so that `docker rm -v` hits `docker-rm-volumes` (the more specific rule) rather than `docker-rm`.
- The `compose-down`/`compose-legacy-down` rules match any `down` subcommand; the `-v` variants hit the more specific `compose-down-volumes`/`compose-legacy-down-volumes` rules first.
- Sub-patterns follow the existing `\s[^|;&\n]*?\bVERB\b` convention to avoid crossing shell separators.

## Alternatives Considered

- **Not blocking `compose down`** (without `-v`): Rejected — stopping and deleting all service containers is destructive enough to warrant blocking in an AI-agent context even when volumes are preserved.
- **Blocking `docker stop` / `docker kill`**: Rejected — containers can be restarted; no data is permanently lost.
- **Blocking `docker exec` shell access**: Out of scope for this iteration; tracked separately as the Docker equivalent of `k8s-exec-shell`.
- **Blocking `docker network rm/prune`**: Rejected — networks are easily recreated with no persistent data at stake.

## Consequences

- `docker rm` without arguments (no targets specified) is not blocked — the pattern requires at least one non-whitespace target to avoid false positives on management subcommands like `docker rm --help`.
- The alias system covers `docker` aliases but not `docker-compose` aliases independently; users must register `docker-compose` aliases separately if needed.
