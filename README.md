# rsh – Rust Security Hook

Ein minimaler Claude-Code-`PreToolUse`-Hook in Rust. Vor jedem `Bash`-Tool-Call prüft `rsh` den Befehl gegen eine Blacklist regulärer Ausdrücke und blockiert ihn bei Treffer, indem es mit Exit-Code `2` und einer Begründung auf stderr terminiert. Claude Code wertet das als "Tool-Call verweigert" und reicht die Meldung ans Modell zurück.

Inspiriert von der Hook-/Init-Mechanik von [rtk-ai/rtk](https://github.com/rtk-ai/rtk), aber bewusst auf einen einzigen Zweck reduziert: Befehle blockieren. Kein Rewriting, kein Proxying.

> **Hinweis:** Die ausgelieferte Blacklist ist absichtlich klein und enthält aktuell nur ein paar destruktive `kubectl`-Operationen (`delete namespace`, `delete --all`, `delete crd`, force-delete). Eigene Regeln pflegst du in `src/blacklist.rs` ein – siehe [Eigene Regeln hinzufügen](#eigene-regeln-hinzufügen).

## Aliase erkennen / pflegen

Regeln mit einem `bin`-Feld (z.B. `kubectl`) matchen nicht nur das exakte Binary, sondern auch alle bekannten Aliase. Aliase liegen in `~/.config/rsh/aliases.json`. Es gibt zwei Wege, sie einzutragen:

```sh
rsh alias kubectl k         # manuell: "k" auf diesem System ist ein Alias für kubectl
rsh detect-aliases          # automatisch: scannt $PATH nach Symlinks/Hardlinks auf kubectl
rsh detect-aliases helm     # gezielter Scan
```

`rsh init` ruft `detect-aliases` für alle Regel-Binaries automatisch mit auf.

**Was erkannt wird**: Symlinks und Hardlinks im `$PATH`, die per `realpath()` auf dasselbe Binary auflösen.
**Was nicht erkannt wird**: Wrapper-Skripte (Shell-Scripte, die `kubectl` aufrufen), Shell-Aliase aus rc-Files (`alias k=kubectl` in `.bashrc` — werden in `bash -c` ohnehin nicht expandiert), umbenannte Kopien des Binaries (`cp $(which kubectl) /tmp/foo`). Determinierte Umgehung bleibt mit einer reinen Regex-Blacklist möglich; das ist eine Designgrenze.

Mit `rsh list` siehst du jederzeit, welche Aliase aktiv in die Patterns eingebaut werden.

## Installation

### One-Liner (Linux / macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh
```

Das Skript:

1. Installiert bei Bedarf Rust über `rustup` (minimal profile).
2. Führt `cargo install --git https://github.com/thePermission/RustSecurityHook.git` aus.
3. Legt das Binary nach `~/.cargo/bin/rsh` ab.

Stelle sicher, dass `~/.cargo/bin` in deinem `PATH` liegt – das Skript warnt dich, falls nicht.

### Manuell aus dem Quellcode

```sh
git clone git@github.com:thePermission/RustSecurityHook.git
cd RustSecurityHook
cargo install --path .
```

### Verifizieren

```sh
rsh --help
rsh list      # zeigt aktuell konfigurierte Regeln (anfangs leer)
```

## Als Claude-Code-Hook registrieren

Nach der Installation einmal registrieren:

```sh
rsh init -g          # global in ~/.claude/settings.json
# oder projektlokal:
rsh init             # in ./.claude/settings.json des aktuellen Verzeichnisses
```

`init` ist idempotent. Wenn `rsh` im `PATH` ist, wird der Hook-Eintrag mit `"command": "rsh"` angelegt, sonst mit dem absoluten Pfad des Binaries.

Zum Entfernen einfach den entsprechenden `PreToolUse`-Eintrag aus der `settings.json` löschen.

## Benutzung

`rsh` wird primär automatisch von Claude Code über stdin aufgerufen. Für lokale Tests:

```sh
rsh check "rm -rf /"              # Blacklist gegen literalen Befehl prüfen
rsh list                          # alle konfigurierten Regeln anzeigen
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | rsh
```

Exit-Codes:

| Code | Bedeutung |
|------|-----------|
| `0`  | Befehl ist erlaubt (oder kein Bash-Tool / kein lesbarer Input) |
| `2`  | Befehl wurde blockiert; Begründung steht auf stderr |

## Eigene Regeln hinzufügen

Regeln liegen in [`src/blacklist.rs`](src/blacklist.rs) im `RAW_RULES`-Array als `(id, bin, sub_pattern, reason)`-Tupel:

```rust
const RAW_RULES: &[(&str, Option<&str>, &str, &str)] = &[
    // bin = Some("kubectl") → die Regex wird zu \b(?:kubectl|<alias>...)\b<sub_pattern>
    ("k8s-delete-namespace",
     Some("kubectl"),
     r"\s[^|;&\n]*?\bdelete\s+(ns|namespace|namespaces)\b",
     "Deletes a Kubernetes namespace ..."),

    // bin = None → sub_pattern wird unverändert verwendet
    ("rm-rf-root",
     None,
     r"\brm\s+(-[a-zA-Z]*[rRfF][a-zA-Z]*\s+)+/(\s|$)",
     "Recursive deletion of root"),
];
```

Der `[^|;&\n]*?`-Block zwischen Binary und Verb erlaubt Flags und Optionen (z.B. `kubectl --context=prod delete ...`) und stoppt an Shell-Trennern (`|`, `;`, `&`, Zeilenende), damit kein Match über Pipes hinweg passiert.

Workflow zum Erweitern:

1. Regel in `RAW_RULES` ergänzen (eindeutige `id`, sie taucht in der Block-Meldung auf).
2. Im `tests`-Modul derselben Datei mindestens einen Treffer- und einen Negativ-Test schreiben.
3. `cargo test` lokal laufen lassen.
4. `cargo install --path .` neu ausführen (oder den `install.sh`-One-Liner) – fertig.

Mit `rsh list` siehst du jederzeit, welche Regeln im installierten Binary aktiv sind.

## Entwicklung

```sh
cargo build --release    # Release-Binary unter target/release/rsh
cargo test               # Unit-Tests in src/blacklist.rs
cargo test <name>        # einzelner Test
cargo run -- list        # Subcommand ohne Install ausführen
```

`Cargo.toml` nutzt `edition = "2024"` – aktueller Stable-Toolchain via `rustup` erforderlich.

## Lizenz

Apache License 2.0 — siehe [LICENSE](LICENSE).
