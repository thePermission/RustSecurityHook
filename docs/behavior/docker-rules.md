# Docker Blocking Rules

`rsh` blocks Docker and Docker Compose commands that can cause irreversible data loss (volume deletion) or bulk removal of containers and images. Both the plugin form (`docker compose`) and the legacy binary (`docker-compose`) are covered.

All Docker rules use `bin = Some("docker")` or `bin = Some("docker-compose")`, so any registered alias (e.g. `d → docker`) is automatically included in the match.

## Docker — Volume Destruction

These rules fire when the command would delete volume data. Volume loss is irreversible without a backup.

| ID | Blocked command | Reason |
|---|---|---|
| `docker-volume-rm` | `docker volume rm <name>` or `volume remove` | Removes named volumes |
| `docker-volume-prune` | `docker volume prune` | Removes all unused volumes in bulk |
| `docker-system-prune-risky` | `docker system prune --volumes` / `-a` / `--all` | Deletes volumes and all images |
| `docker-rm-volumes` | `docker rm -v` / `--volumes <container>` | Removes container and its anonymous volumes |
| `compose-down-volumes` | `docker compose down -v` / `--volumes` | Removes all service containers and their volumes |
| `compose-legacy-down-volumes` | `docker-compose down -v` / `--volumes` | Same via legacy CLI |
| `compose-rm-volumes` | `docker compose rm -v` / `--volumes` | Removes stopped service containers and anonymous volumes |
| `compose-legacy-rm-volumes` | `docker-compose rm -v` / `--volumes` | Same via legacy CLI |

`docker system prune` **without** `--volumes`, `-a`, or `--all` is **not** blocked — it only removes stopped containers, dangling images, and unused networks, which are recoverable.

## Docker — Container/Image Cleanup

These rules fire when the command removes containers or images. Named volume data is not lost, but the operations are bulk-destructive enough to warrant blocking in an AI-agent context.

| ID | Blocked command | Reason |
|---|---|---|
| `docker-container-prune` | `docker container prune` | Removes all stopped containers in bulk |
| `docker-image-prune` | `docker image prune` | Removes dangling or all unused images |
| `docker-image-rm` | `docker image rm` / `docker image remove` | Removes images by name or ID |
| `docker-rmi` | `docker rmi <image>` | Removes images (legacy command) |
| `docker-rm` | `docker rm <container>` | Removes one or more containers |
| `compose-down` | `docker compose down` | Stops and removes all service containers |
| `compose-legacy-down` | `docker-compose down` | Same via legacy CLI |

## Rule ordering and specificity

Volume Destruction rules appear before Container/Image Cleanup rules in `RAW_RULES`. This ensures that `docker rm -v mycontainer` hits `docker-rm-volumes` (the more specific, higher-severity rule) rather than `docker-rm`.

Similarly, `docker compose down -v` hits `compose-down-volumes` before `compose-down`.

## What is not blocked

- `docker stop` / `docker kill` — containers can be restarted; no data is lost.
- `docker network rm` / `docker network prune` — networks are trivially recreated; no persistent data is at stake.
- `docker build` / `docker pull` — no destructive effect.
- `docker exec` shell access — tracked separately as the Docker equivalent of `k8s-exec-shell`; not in scope for this iteration.
- `docker system prune` without risky flags — lower blast radius (no volume data deleted).

## Adding aliases

If you use a shell alias or symlink for `docker` or `docker-compose`, register it so rules expand correctly:

```sh
rsh alias docker d          # "d" is treated as "docker"
rsh detect-aliases docker   # auto-detect symlinks/hardlinks in $PATH
```
