# Docker Blacklist Rules — Design Spec

**Date:** 2026-05-17
**Status:** Approved

## Overview

Add Docker and Docker Compose commands to the `rsh` blacklist that can cause
irreversible data loss (volumes) or bulk removal of containers and images.
Both the new plugin form (`docker compose`) and the legacy binary
(`docker-compose`) are covered.

## Categories

### Docker — Volume Destruction

Rules that can cause irreversible data loss because they delete volume data.

| ID | Command | Blocked Pattern | Reason |
|---|---|---|---|
| `docker-volume-rm` | `docker volume rm <name>` | `volume rm` | Removes named volumes — irreversible data loss |
| `docker-volume-prune` | `docker volume prune` | `volume prune` | Removes all unused volumes — bulk irreversible data loss |
| `docker-system-prune-risky` | `docker system prune --volumes` / `-a` / `--all` | `system prune` + `--volumes`/`-a`/`--all` | Deletes volumes and all images — high blast radius |
| `docker-rm-volumes` | `docker rm -v` / `--volumes` | `rm` + `-v`/`--volumes` flag | Removes container and its anonymous volumes |
| `compose-down-volumes` | `docker compose down -v` / `--volumes` | `compose down` + `-v`/`--volumes` flag | Removes all service containers and their volumes |
| `compose-legacy-down-volumes` | `docker-compose down -v` / `--volumes` | `down` + `-v`/`--volumes` flag | Same risk via legacy CLI |
| `compose-rm-volumes` | `docker compose rm -v` / `--volumes` | `compose rm` + `-v`/`--volumes` flag | Removes stopped service containers and anonymous volumes |
| `compose-legacy-rm-volumes` | `docker-compose rm -v` / `--volumes` | `rm` + `-v`/`--volumes` flag | Same risk via legacy CLI |

**Note on `docker system prune`:** Blocked only when `--volumes`, `-a`, or `--all`
is present. Without these flags the blast radius is lower (only stopped
containers, dangling images, unused networks — no volume data).

### Docker — Container/Image Cleanup

Rules that remove containers or images. Named volume data is not lost, but the
operations are bulk/destructive enough to warrant blocking in an AI-agent context.

| ID | Command | Blocked Pattern | Reason |
|---|---|---|---|
| `docker-container-prune` | `docker container prune` | `container prune` | Removes all stopped containers in bulk |
| `docker-rm` | `docker rm <name>` | `rm` + at least one target | Removes one or more containers |
| `docker-rmi` | `docker rmi <image>` | `rmi` + at least one target | Removes images (legacy command) |
| `docker-image-rm` | `docker image rm` / `image remove` | `image rm`/`image remove` | Removes images by name or ID |
| `docker-image-prune` | `docker image prune` | `image prune` | Removes dangling or all unused images |
| `compose-down` | `docker compose down` | `compose down` | Stops and removes all service containers (volumes kept) |
| `compose-legacy-down` | `docker-compose down` | `down` | Stops and removes all service containers via legacy CLI |

## Implementation Details

### Binary Binding

- Rules for `docker <subcommand>` use `bin = Some("docker")` so the alias system
  automatically expands any registered aliases (e.g. `d` → `docker`).
- Rules for `docker compose <subcommand>` also use `bin = Some("docker")` with
  `\bcompose\b` in the sub-pattern.
- Rules for `docker-compose <subcommand>` use `bin = Some("docker-compose")`.

### Sub-Pattern Convention

Following the existing kubectl convention:

```
\s[^|;&\n]*?\bVERB\b...
```

- `\s` — requires whitespace before the verb (the binary already anchors the
  start via `\b(?:docker|...)\b`).
- `[^|;&\n]*?` — lazy match that does not cross shell separators.
- Flags like `-v` are matched with `(?:--volumes\b|-[a-zA-Z]*v\b)` to catch
  both the long form and combined short flags such as `-fv`.

### Rule Ordering

Volume Destruction rules are placed before Container/Image Cleanup rules in
`RAW_RULES`. This ensures that `docker rm -v` hits `docker-rm-volumes` (the
more specific/severe rule) before `docker-rm`.

### Tests

Each rule gets at least one positive test (blocked) and one negative test
(allowed). A `rule_ids_are_distinct_and_match_expected_set` assertion covers
the full ID list and must be updated.

## Out of Scope

- `docker network rm` / `docker network prune` — networks are easily recreated,
  no persistent data at stake.
- `docker build` / `docker pull` — no destructive effect.
- `docker stop` / `docker kill` — containers can be restarted.
- `docker exec` shell access — not in scope for this iteration (separate concern
  from the kubectl equivalent).
