# Docker Checker

`DockerChecker` handles `docker` and `docker-compose` commands (and registered aliases). Activates when content contains `docker`, `docker-compose`, or a known alias. One type of check: **regex blacklist only** — no forbid check for Docker.

## Volume Destruction

| ID | Blocked Command | Reason |
|---|---|---|
| `docker-volume-rm` | `docker volume rm <name>` or `volume remove` | Removes named volumes — irreversible data loss |
| `docker-volume-prune` | `docker volume prune` | Removes all unused volumes in bulk — bulk irreversible data loss |
| `docker-system-prune-risky` | `docker system prune --volumes` / `-a` / `--all` | Deletes volumes and all images — high blast radius |
| `docker-rm-volumes` | `docker rm -v` / `--volumes <container>` | Removes container and its anonymous volumes — irreversible data loss |
| `compose-down-volumes` | `docker compose down -v` / `--volumes` | Removes all service containers and their volumes |
| `compose-legacy-down-volumes` | `docker-compose down -v` / `--volumes` | Same via legacy CLI |
| `compose-rm-volumes` | `docker compose rm -v` / `--volumes` | Removes stopped service containers and their anonymous volumes |
| `compose-legacy-rm-volumes` | `docker-compose rm -v` / `--volumes` | Same via legacy CLI |

**Note:** `docker system prune` without `--volumes`, `-a`, or `--all` is **not blocked**.

## Container and Image Cleanup

| ID | Blocked Command | Reason |
|---|---|---|
| `docker-container-prune` | `docker container prune` | Removes all stopped containers in bulk |
| `docker-image-prune` | `docker image prune` | Removes dangling or all unused images |
| `docker-image-rm` | `docker image rm` / `docker image remove` | Removes images by name or ID |
| `docker-rmi` | `docker rmi <image>` | Removes images (legacy command) |
| `docker-rm` | `docker rm <container>` | Removes one or more containers |
| `compose-down` | `docker compose down` | Stops and removes all service containers |
| `compose-legacy-down` | `docker-compose down` | Same via legacy CLI |

**Rule ordering note:** Volume Destruction rules are evaluated first. `docker rm -v mycontainer` hits `docker-rm-volumes` (higher severity) rather than `docker-rm`.

## What is Not Blocked

- `docker stop` / `docker kill` — containers can be restarted
- `docker network rm` / `docker network prune` — trivially recreated
- `docker build` / `docker pull` — no destructive effect

## Aliases

```sh
rsh alias docker d
rsh detect-aliases docker
```

See [[alias-system]].

## Disabling Rules

```sh
rsh rule disable docker-volume-rm
rsh rule enable docker-volume-rm
```

See [[rules-and-categories]].
