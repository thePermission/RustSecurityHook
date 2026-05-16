# rsh – Rust Security Hook

A lean Claude Code `PreToolUse` hook. Before every `Bash` tool call, `rsh` checks the command against a blacklist and blocks it on a match by exiting with a reason on stderr. Claude Code treats that as a refused tool call and surfaces the message back to the model.

Out of the box, `rsh` ships with a small set of rules for destructive `kubectl` operations (`delete namespace`, `delete --all`, `delete crd`, force-delete). You can always see which rules are active with `rsh list`.

## Installation

All installers download a prebuilt binary from the latest [GitHub release](https://github.com/thePermission/RustSecurityHook/releases). No build tools or Rust toolchain required.

### Linux / macOS

```sh
curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh
```

Installs to `~/.local/bin/rsh` by default.

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\Programs\rsh\rsh.exe` by default and adds that directory to your user `PATH` automatically (you may need to open a new terminal to pick it up).

### Supported platforms

| OS      | Architecture                       |
|---------|------------------------------------|
| Linux   | x86_64, aarch64                    |
| macOS   | x86_64, Apple Silicon (aarch64)    |
| Windows | x86_64                             |

### Optional environment variables

| Variable          | Effect                                                                    |
|-------------------|---------------------------------------------------------------------------|
| `RSH_VERSION`     | Install a specific release tag (e.g. `v0.2.0`). Default: latest release.  |
| `RSH_INSTALL_DIR` | Install into a different directory.                                       |

Make sure your install directory is on your `PATH` — the script warns you if it isn't.

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

## Command overview

```text
rsh                          Hook mode (invoked by Claude Code)
rsh init [-g|--global]       Register the hook in settings.json
rsh check "<command>"        Run the blacklist against a command
rsh list                     Show all rules and aliases
rsh alias <cmd> <alias>      Register an alias
rsh detect-aliases [cmd]     Auto-detect aliases
rsh help    (-h, --help)     Show help
rsh version (-v, --version)  Show version
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
