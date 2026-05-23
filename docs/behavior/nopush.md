# Per-Project Push Blocker

`rsh forbid push` marks the current project as read-only for push operations. It is opt-in and project-local — no global configuration, no central store.

## Activation

```sh
rsh forbid push     # block push; creates .rsh-nopush, updates .gitignore
rsh allow push      # re-enable push; removes .rsh-nopush
```

## Blocked commands (when `.rsh-nopush` is present)

| Command | Variants covered |
|---|---|
| `git push` | All flags and arguments (`--force`, `-f`, `--force-with-lease`, `--delete`, etc.) |
| `gh pr merge` | All flags |
| `glab mr merge` | All flags |
| `glab mr create` | All flags |

Other git operations (`pull`, `fetch`, `status`, etc.) are not affected.

## Block message

```
rsh blocked push: this project is marked read-only (.rsh-nopush)
hint: run 'rsh allow push' to re-enable pushing
```

## gitignore

`rsh forbid push` appends `.rsh-nopush` to `.gitignore` (creates the file if absent). The entry is not removed by `rsh allow push` — it is harmless and avoids an extra diff.

## Self-protection

Agents cannot run `rsh allow push` (rule: `rsh-protect-allow`) or directly delete/rename `.rsh-nopush` (rule: `rsh-guard-flag-file`). Only a developer running `rsh` interactively can re-enable pushing.
