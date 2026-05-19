# Secret File Protection — Design Spec

**Date:** 2026-05-19  
**Status:** Approved

## Problem

`rsh` currently blocks destructive shell commands and protects its own configuration directory, but it does not prevent an AI model from reading files that contain secrets (API keys, private keys, cloud credentials, etc.). A model using the `Read` tool or running `cat .env` via Bash can silently exfiltrate credentials.

## Goal

Block AI access to files that commonly contain secrets, across all three access vectors:

- **`Read` tool** — direct file read by the model
- **`Bash` tool** — any shell command that receives a secret file as an argument
- **`Write`/`Edit` tools** — writing to secret files (overwrite or leak risk)

Each rule can be toggled individually using the existing `rsh rule` mechanism.

## Architecture

### New module: `src/secrets.rs`

Holds a static `RAW_SECRET_RULES` list typed as `&[(&str, &str, &[&str], &str)]`:

```
(id, category, patterns, reason)
```

Multiple glob patterns per rule are supported (e.g. `secret-dotenv` covers `.env`, `.env.*`, `*.env`).

Public API:

```rust
pub struct SecretRule {
    pub id: &'static str,
    pub category: &'static str,
    pub patterns: &'static [&'static str],
    pub reason: &'static str,
}

pub struct Hit {
    pub id: &'static str,
    pub reason: &'static str,
}

/// Returns the first matching enabled rule for the given file path, or None.
pub fn check_path(path: &str) -> Option<Hit>

/// All rules, for use in `rsh list`.
pub fn all_rules() -> &'static [SecretRule]
```

`check_path` skips rules whose ID appears in `disabled::disabled_rules()` — same mechanism used by `blacklist`.

### Glob matching (no new crate)

All patterns follow the `**/...` schema. The internal matcher resolves them to simple comparisons:

| Pattern form | Match logic |
|---|---|
| `**/<name>` | `basename(path) == name` |
| `**/*.<ext>` | `path.ends_with(".<ext>")` |
| `**/<name>.*` | `basename(path).starts_with("<name>.")` |
| `**/<dir>/<name>` | path ends with `/<dir>/<name>` |
| `**/*.env` | `path.ends_with(".env")` |

`Cargo.toml` is unchanged — no new dependency.

### Hook dispatch changes (`src/main.rs`)

**`Read` tool** (currently ignored, passes through):

```
tool_name == "Read"
  -> secrets::check_path(tool_input.file_path)
    -> hit: exit 2, stderr message
    -> no hit: exit 0
```

**`Write` / `Edit` tools** (currently: protected-path check -> content scan):

```
tool_name == "Write" | "Edit"
  -> is_protected_path(file_path)  [existing]
  -> secrets::check_path(file_path)  [NEW — before content scan]
  -> run_check_content(content)  [existing]
```

**`Bash` tool** — new `SecretFileChecker` enters the parallel pipeline:

```
segments -> run_parallel_checks([
    KubectlChecker, HelmChecker, DockerChecker, RshChecker,
    FallbackChecker,
    SecretFileChecker  <- NEW
])
```

### `SecretFileChecker`

Implements the existing `ToolChecker` trait:

- `bins()` -> `vec![]` (always runs, like `FallbackChecker`)
- `check(content: &str)`:
  1. Tokenize `content` via `shell::tokenize`
  2. Skip token 0 (command name) and any token starting with `-`
  3. For each remaining token: `secrets::check_path(token)`
  4. Return the first hit, or `None`

### Block messages

```
rsh blocked read of secret file (rule: secret-dotenv): Environment file may contain API keys or passwords
rsh blocked write to secret file (rule: secret-ssh-private-key): SSH private key — writing could overwrite or leak credentials
rsh blocked bash access to secret file (rule: secret-aws-credentials): AWS credentials file
```

### `rsh list` output

Secret rules appear as a separate category group after the existing blacklist rules, using the same tabular format.

## Rule Catalogue

### Environment & App Secrets

| ID | Patterns | Reason |
|----|----------|--------|
| `secret-dotenv` | `**/.env`, `**/.env.*`, `**/*.env` | Environment files often containing API keys and passwords |
| `secret-npmrc` | `**/.npmrc` | npm auth tokens for private registries |
| `secret-pip-conf` | `**/pip.conf`, `**/.pip/pip.conf` | pip index URLs with embedded credentials |
| `secret-git-credentials` | `**/.git-credentials` | Git credential helper plaintext store |
| `secret-netrc` | `**/.netrc` | FTP/HTTP credentials |
| `secret-htpasswd` | `**/.htpasswd` | Web server password hashes |
| `secret-maven-settings` | `**/settings.xml` | Maven settings with Nexus/Artifactory repository credentials |

### Cryptographic Keys

| ID | Patterns | Reason |
|----|----------|--------|
| `secret-pem` | `**/*.pem` | TLS certificates and private keys |
| `secret-key-file` | `**/*.key` | Generic key files |
| `secret-p12` | `**/*.p12`, `**/*.pfx` | PKCS#12 key stores |
| `secret-pgp` | `**/*.gpg`, `**/*.asc` | PGP encrypted/signed files |
| `secret-jks` | `**/*.jks`, `**/*.keystore` | Java key stores |

### SSH

| ID | Patterns | Reason |
|----|----------|--------|
| `secret-ssh-private-key` | `**/id_rsa`, `**/id_ed25519`, `**/id_ecdsa`, `**/id_dsa` | SSH private keys |
| `secret-ssh-config` | `**/.ssh/config` | SSH config containing host and identity file paths |

### Cloud & Infrastructure

| ID | Patterns | Reason |
|----|----------|--------|
| `secret-aws-credentials` | `**/.aws/credentials` | AWS access key ID and secret |
| `secret-gcloud-key` | `**/application_default_credentials.json` | GCP service account key |
| `secret-kubeconfig` | `**/.kube/config` | Kubernetes cluster credentials |
| `secret-docker-config` | `**/.docker/config.json` | Docker registry auth tokens |
| `secret-vault-token` | `**/.vault-token` | HashiCorp Vault token |
| `secret-shadow` | `**/etc/shadow`, `**/etc/master.passwd` | System password hashes |

## Toggle

Secret rule IDs (`secret-*`) use the same `rsh rule` subcommand and `disabled-rules.json` as blacklist rules.
The on-disk state file is the same one used by the existing rule-toggle system (see `src/disabled.rs`).

## Testing

Each rule needs:
- At least one positive test: `check_path` returns `Some` for a matching path
- At least one negative test: `check_path` returns `None` for a non-matching path
- Edge cases: paths with and without leading `/`, Windows backslash paths, paths that share a prefix with a pattern but do not match (e.g. `settings.xml.bak` vs `settings.xml`)

`SecretFileChecker` tests:
- Bash segment `cat /home/user/.env` -> hit
- Bash segment `echo hello` -> no hit
- Bash segment with flags: `cp -r .env /tmp/backup` -> hit (`.env` is a non-flag argument)
- Bash segment `git status` -> no hit

## Out of Scope

- Content-based secret detection (scanning file contents for key patterns) — a separate, larger feature
- Custom user-defined secret rules — the toggle mechanism is sufficient for now
- Detecting secrets in environment variables passed via Bash
