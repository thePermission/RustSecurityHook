# rsh – Rust Security Hook

A lean Claude Code `PreToolUse` hook. Before every `Bash` tool call, `rsh` checks the command against a blacklist and blocks it on a match by exiting with a reason on stderr. Claude Code treats that as a refused tool call and surfaces the message back to the model.

Out of the box, `rsh` ships with 40 rules across eleven categories:

| Category | Rules |
|---|---|
| Kubernetes — Destructive | delete namespace/ns, delete --all, delete crd, force-delete, delete pv/pvc, delete clusterrole/binding, delete node, delete deployment/statefulset/daemonset |
| Kubernetes — Pod Access | exec shell, run --privileged, debug node/, attach, proxy, cp (local → pod) |
| Kubernetes — Privilege Escalation | create clusterrolebinding --clusterrole=cluster-admin, apply -f http(s):// |
| Kubernetes — Service Disruption | drain |
| Kubernetes — Subprocess Bypass | kubectl delete/exec in subprocess argument lists |
| Helm | uninstall / delete |
| Helm — Subprocess Bypass | helm uninstall in subprocess argument lists |
| SQL — Destructive DML | DELETE FROM, TRUNCATE |
| SQL — Destructive DDL | DROP (table/db/schema/…), ALTER TABLE, CREATE TABLE/DATABASE/SCHEMA |
| Docker — Volume Destruction | volume rm/prune, system prune --volumes/-a, rm -v, compose down/rm -v (plugin + legacy) |
| Docker — Container/Image Cleanup | container prune, image prune/rm/rmi, rm, compose down (plugin + legacy) |

Run `rsh list` to see all active rules with their full patterns and reasons.

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

By default the binary is installed to `~/.cargo/bin` (or the platform equivalent) and that directory is appended to your `PATH` automatically.

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
TAG=v0.2.0
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

## Register as a Claude Code hook

Run once after installation:

```sh
rsh init -g          # global, in ~/.claude/settings.json
# or project-local:
rsh init             # in ./.claude/settings.json of the current directory
```

`init` is idempotent (running it multiple times never duplicates entries) and afterwards automatically scans your `$PATH` for known aliases of `kubectl` and other rule binaries.

To remove the hook, delete the corresponding `PreToolUse` entry from `settings.json`.

## Usage

`rsh` is primarily invoked automatically by Claude Code — after `rsh init` you don't need to do anything else. For manual inspection:

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

## Forbidden clusters and namespaces

Beyond the regex blacklist, `rsh` can block any kubectl- or helm-aliased command that targets a forbidden cluster or namespace. This catches commands that aren't destructive on their own but should never run against a specific environment (e.g. anything against the production cluster).

```sh
rsh forbid cluster prod-eu          # block commands hitting context "prod-eu"
rsh forbid namespace kube-system    # block commands hitting namespace "kube-system"
rsh forbid list                     # show current forbid lists
rsh forbid remove cluster prod-eu   # remove an entry
```

When a kubectl/helm command runs, `rsh` checks:

1. Does the command contain `--context=<value>` (or `--kube-context=<value>` for helm)? If so, compare the value with the forbidden cluster list.
2. Does it contain `--namespace=<value>` or `-n <value>`? Compare with the forbidden namespace list.
3. If neither flag is present, `rsh` asks `kubectl` for the current context (`kubectl config current-context`) and the current namespace, and checks those.

Storage: `~/.config/rsh/forbidden.json` (or the platform equivalent).

## Command overview

```text
rsh                          Hook mode (invoked by Claude Code)
rsh init [-g|--global]       Register the hook in settings.json
rsh check "<command>"        Run the blacklist + forbid checks against a command
rsh list                     Show all rules, forbidden entries, and aliases
rsh alias <cmd> <alias>      Register an alias
rsh detect-aliases [cmd]     Auto-detect aliases
rsh forbid ...               Manage forbidden clusters/namespaces (see above)
rsh help    (-h, --help)     Show help
rsh version (-v, --version)  Show version
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
