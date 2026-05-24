# Secret File Protection

`rsh` blocks AI model access to files that commonly contain credentials, private keys,
or other secrets. The check happens at the tool boundary before any content reaches the
model's context window.

## Blocked surfaces

| Tool / command    | What is checked                                        |
|-------------------|--------------------------------------------------------|
| `Read`            | `file_path` field                                      |
| `Write`           | `file_path` field                                      |
| `Edit`            | `file_path` field                                      |
| `Bash`            | every non-flag token; value side of `--flag=VALUE`; value side of leading `KEY=VALUE` env-assignment |

## Rule catalogue

20 rules across 5 categories. Each rule has a stable `id` used in block messages and
the disable/enable mechanism.

| Category                  | IDs |
|---------------------------|-----|
| Secret Files — Environment | `secret-dotenv`, `secret-npmrc`, `secret-pip-conf`, `secret-git-credentials`, `secret-netrc`, `secret-htpasswd`, `secret-maven-settings` |
| Secret Files — Cryptographic Keys | `secret-pem`, `secret-key-file`, `secret-p12`, `secret-pgp`, `secret-jks` |
| Secret Files — SSH        | `secret-ssh-private-key`, `secret-ssh-config` |
| Secret Files — Cloud      | `secret-aws-credentials`, `secret-gcloud-key`, `secret-kubeconfig`, `secret-docker-config`, `secret-vault-token` |
| Secret Files — System     | `secret-shadow` |

Run `rsh list` to see all rules, their patterns, and reasons.

## Glob pattern matching

Patterns use the `**/` prefix. Four forms are supported:

| Form                  | Example pattern          | Matches                                 |
|-----------------------|--------------------------|-----------------------------------------|
| Exact basename        | `**/.env`                | any path whose last component is `.env` |
| Extension             | `**/*.pem`               | basename ends with `.pem`, non-empty stem |
| Stem wildcard         | `**/.env.*`              | basename starts with `.env.`            |
| Two-component path    | `**/.aws/credentials`    | last two components match exactly       |

Matching is **case-insensitive** (ASCII fold), so `.ENV`, `.Env`, `CERT.PEM`, and
`.AWS/Credentials` are all blocked on any operating system.

## Disabling individual rules

```bash
rsh rule disable secret-dotenv     # allow .env file access
rsh rule enable  secret-dotenv     # restore blocking
rsh rule list                      # show all disabled rules
```

Disabled rule IDs are persisted in `~/.config/rsh/disabled.json`.

## Known limitations

The following bypass vectors are not detected because `rsh` receives the command string
before the shell processes it:

- **Shell glob expansion** — `cat /project/.env*` is seen as the literal token `.env*`
  and does not match `**/.env`.
- **Attached short options** — `curl -K/etc/ssl/server.pem` is skipped because the
  token starts with `-` but contains no `=`.
- **Variable indirection** — `F=/project/.env; cat $F` — only the assignment token is
  checked; the later `$F` reference is not expanded.

These are documented non-goals. The common AI-agent patterns (explicit paths, long
options with `=`, and env-prefix assignments) are all covered.
