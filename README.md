# rsh – Rust Security Hook

A lean Claude Code and Codex `PreToolUse` hook. Before every protected tool call, `rsh` checks the command against a blacklist and blocks it on a match by exiting with a reason on stderr. Claude Code and Codex treat that as a refused tool call and surface the message back to the model.

Out of the box, `rsh` covers:

- **kubectl** — destructive deletes, pod access, privilege escalation, service disruption
- **helm** — release uninstall/delete
- **docker / docker-compose** — volume deletion, container and image cleanup
- **SQL clients** (`psql`, `mysql`, `sqlite3`, …) — destructive DML and DDL keywords, matched against any binary
- **Shell scripts** — when a command invokes a script (`bash script.sh`, `./deploy.sh`, `source file`, …), `rsh` reads and scans the script content before execution

See [`docs/rules.md`](docs/rules.md) for the full list of 45 rules grouped by binary, or run `rsh list` to inspect the active rules at any time.

## Scope and limitations

`rsh` is a safety net against **accidental** damage — the kind that happens when a model runs a destructive command because of a misunderstanding, an incorrect assumption, or simple inattentiveness. It is not a security boundary.

Anyone who deliberately wants to bypass the hook can always do so: by unregistering it, by passing commands through an unmonitored shell, or by constructing input that avoids the patterns. If your threat model includes adversarial or malicious actors, `rsh` alone is not sufficient. Use it as one layer in a broader defence strategy, not as a hard guarantee.

## Installation

All installers download a prebuilt binary from the latest [GitHub release](https://github.com/thePermission/RustSecurityHook/releases) and verify its SHA256 checksum before extracting. No build tools or Rust toolchain required.

### Linux / macOS

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/thePermission/RustSecurityHook/releases/latest/download/rsh-installer.sh | sh
```

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://github.com/thePermission/RustSecurityHook/releases/latest/download/rsh-installer.ps1 | iex"
```

By default the binary is installed to `~/.local/bin` (Windows: `%LOCALAPPDATA%\Programs\rsh\bin`) and that directory is appended to your `PATH` automatically. No Rust toolchain required.

### Supported platforms

| OS      | Architecture                       |
|---------|------------------------------------|
| Linux   | x86_64 (musl), aarch64 (gnu)       |
| macOS   | x86_64, Apple Silicon (aarch64)    |
| Windows | x86_64                             |

### Manual download

If you prefer to install manually, the [releases page](https://github.com/thePermission/RustSecurityHook/releases) lists one archive per platform plus its `.sha256` checksum file:

```sh
# Linux x86_64 example
TAG=v0.8.0
curl -fsSL -O https://github.com/thePermission/RustSecurityHook/releases/download/$TAG/rsh-x86_64-unknown-linux-musl.tar.xz
curl -fsSL -O https://github.com/thePermission/RustSecurityHook/releases/download/$TAG/rsh-x86_64-unknown-linux-musl.tar.xz.sha256
sha256sum -c rsh-x86_64-unknown-linux-musl.tar.xz.sha256
tar -xJf rsh-x86_64-unknown-linux-musl.tar.xz
```

### Verify

```sh
rsh --version
rsh --help
```

## Register as a Claude Code or Codex hook

Run once after installation:

```sh
rsh init -g                  # auto-detect and install globally
rsh init                     # auto-detect and install project-locally
rsh init --tool claude       # force Claude only
rsh init --tool codex        # force Codex only
rsh init --tool all -g       # install both globally
```

Auto-detection installs into every supported tool found on the machine:

- Claude: `~/.claude/settings.json` or `./.claude/settings.json`
- Codex: `~/.codex/hooks.json` or `./.codex/hooks.json`

`init` is idempotent (running it multiple times never duplicates entries) and afterwards automatically scans your `$PATH` for known aliases of `kubectl` and other rule binaries.

To remove the hook, delete the corresponding `PreToolUse` entry from the relevant config file.

## Usage

`rsh` is primarily invoked automatically by Claude Code or Codex — after `rsh init` you don't need to do anything else. For manual inspection:

```sh
rsh list                                # show all rules and aliases
rsh check "kubectl delete ns prod"      # test a literal command against the blacklist
```

Exit codes (relevant when running as a hook):

| Code | Meaning                                                             |
|------|---------------------------------------------------------------------|
| `0`  | Command is allowed                                                  |
| `2`  | Command is blocked; reason printed to stderr                        |

## Managing aliases

The blacklist matches not just the exact binary name (e.g. `kubectl`) but also any registered aliases. Aliases live in `~/.config/rsh/aliases.json`.

```sh
rsh alias kubectl k          # manually register: "k" points to kubectl
rsh detect-aliases           # auto-scan: find aliases for all rule binaries in $PATH
rsh detect-aliases helm      # auto-scan for a specific command
```

**Detected automatically:** symlinks and hardlinks in `$PATH` whose `realpath()` resolves to the same binary.

**Not detected:** wrapper scripts, shell aliases from `.bashrc`/`.zshrc` (which `bash -c` doesn't expand anyway), or renamed copies of the binary. A pure text blacklist can't defeat determined evasion.

Use `rsh list` at any time to see which aliases are baked into the rules.

## Forbidden clusters, namespaces, and databases

Beyond the regex blacklist, `rsh` can block any kubectl- or helm-aliased command that targets a forbidden cluster or namespace, and any supported SQL client command that targets a forbidden database host. This catches commands that aren't destructive on their own but should never run against a specific environment (e.g. anything against the production cluster or a production database).

```sh
rsh forbid cluster prod-eu          # block commands hitting context "prod-eu"
rsh forbid namespace kube-system    # block commands hitting namespace "kube-system"
rsh forbid database prod-db.host    # block SQL clients targeting this host
rsh forbid list                     # show current forbid lists
rsh forbid remove cluster prod-eu   # remove an entry
```

When a kubectl/helm command runs, `rsh` checks:

1. Does the command contain `--context=<value>` (or `--kube-context=<value>` for helm)? If so, compare the value with the forbidden cluster list.
2. Does it contain `--namespace=<value>` or `-n <value>`? Compare with the forbidden namespace list.
3. If neither flag is present, `rsh` asks `kubectl` for the current context (`kubectl config current-context`) and the current namespace, and checks those.

When a supported SQL client runs, `rsh` extracts the target hostname from a connection URL or a `-h` / `--host` flag and compares it with the forbidden database list.

Storage: `~/.config/rsh/forbidden.json` (or the platform equivalent).

## Command overview

```text
rsh                          Hook mode (invoked by Claude Code or Codex)
rsh init [-g|--global] [--tool claude|codex|all]
                             Register the hook in the matching config file(s)
rsh check "<command>"        Run the blacklist + forbid checks against a command
rsh list                     Show all rules, forbidden entries, and aliases
rsh alias <cmd> <alias>      Register an alias
rsh detect-aliases [cmd]     Auto-detect aliases
rsh forbid ...               Manage forbidden clusters/namespaces (see above)
rsh completions <shell>      Print shell completion script to stdout (bash, zsh, fish, powershell, elvish)
rsh help    (-h, --help)     Show help
rsh --version (-V)           Show version
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
