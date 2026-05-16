# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Projekt

`rsh` (Rust Security Hook) ist ein Single-Binary CLI, das als Claude Code **PreToolUse-Hook** registriert wird und jeden geplanten `Bash`-Tool-Call gegen eine Blacklist regulärer Ausdrücke prüft. Trifft eine Regel, wird der Aufruf mit Exit-Code 2 und einer stderr-Begründung blockiert — Claude Code interpretiert das als "Tool-Call verweigert" und gibt die Meldung an das Modell zurück.

Inspiration ist die Hook-/Init-Mechanik von [rtk-ai/rtk](https://github.com/rtk-ai/rtk), aber `rsh` ist bewusst minimal: nur Blocking, kein Rewriting, kein Proxying.

**Status der Blacklist**: kuratierter Mini-Satz an destruktiven `kubectl`-Operationen (delete namespace/crd, `--all`, force-delete). Weitere Regeln werden vom Nutzer in `RAW_RULES` (`src/blacklist.rs`) ergänzt.

## Workflow

```bash
cargo install --path .   # rsh in ~/.cargo/bin installieren (muss im PATH sein)
rsh init -g              # Hook in ~/.claude/settings.json eintragen (global)
rsh init                 # Alternativ: ./.claude/settings.json im aktuellen Projekt
```

Für Endnutzer-Installation existieren zusätzlich `README.md` und `install.sh` (One-Liner: `curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh`). Das Skript installiert bei Bedarf rustup und führt dann `cargo install --git ...` aus. Bei Änderungen am Installationsweg beide Dateien synchron halten.

`init` ist idempotent (Dedup über das `command`-Feld). Wenn `rsh` im PATH liegt, wird `"rsh"` als Hook-Command eingetragen — sonst der absolute Pfad des aktuell laufenden Binaries. Empfohlen ist `cargo install --path .` zuerst, damit ein erneutes Build des Repos nicht den Hook bricht.

## Build / Test

```bash
cargo build --release        # Release-Binary unter target/release/rsh
cargo test                   # Unit-Tests (in src/blacklist.rs)
cargo test <name>            # einzelner Test, z.B. cargo test empty_blacklist_allows_everything
rsh check "rm -rf /"         # Blacklist gegen literalen Command-String prüfen
```

Manuelle Hook-Simulation (genau so ruft Claude Code das Binary auf):

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | rsh
# exit 0 → durchlassen (leere Blacklist)
```

## Architektur

Das Binary unterscheidet seinen Modus anhand von `argv[1]`:

| Modus | Trigger | Verhalten |
|---|---|---|
| Hook (default) | kein/unbekanntes argv[1] | Liest PreToolUse-JSON von stdin, extrahiert `tool_input.command`, läuft durch Blacklist |
| `check` | `rsh check "<cmd>"` | Prüft das Argument direkt — fürs lokale Testen einer Regel |
| `init` | `rsh init [-g\|--global]` | Patcht `settings.json` (mit `-g` global in `~/.claude/`, sonst projektlokal `./.claude/`) |
| `list` | `rsh list` (alias `rules`) | Listet alle Regeln (id, reason, bin, vollständig expandierte Regex) sowie die Alias-Map |
| `alias` | `rsh alias <cmd> <alias>` | Trägt einen Alias in `~/.config/rsh/aliases.json` ein (z.B. `rsh alias kubectl k`) |
| `detect-aliases` | `rsh detect-aliases [cmd]` | Scannt `$PATH` nach Symlinks/Hardlinks, die per `realpath` auf `cmd` (oder alle bin-Regeln) auflösen, und ergänzt die Alias-Map |
| `help` | `rsh help` / `-h` / `--help` | Usage-Übersicht |

Hook-Input-Schema (Claude Code PreToolUse-Event): JSON mit mindestens `tool_name` (string) und `tool_input` (object). Für den `Bash`-Tool steckt der auszuführende Befehl in `tool_input.command`. Bei anderen Tool-Namen oder leerem/ungültigem stdin lässt `rsh` den Call durchgehen (Exit 0) — Fail-Open ist Absicht, damit ein Crash im Hook nicht die ganze Session lahmlegt.

**Blacklist-Modul** (`src/blacklist.rs`): zentrale Stelle für neue Regeln. Regeln sind `(id, Option<bin>, sub_pattern, reason)`-Tupel in `RAW_RULES`. Bei `Some(bin)` wird zur LazyLock-Init die volle Regex als `\b(?:bin|alias1|alias2|...)\b<sub_pattern>` zusammengesetzt, wobei die Aliases aus `~/.config/rsh/aliases.json` (Modul `src/aliases.rs`) gezogen werden. Bei `None` wird `sub_pattern` direkt verwendet. Konvention für die Sub-Pattern bei kubectl-ähnlichen Tools: mit `\s[^|;&\n]*?\bVERB\b` beginnen, damit Flags zwischen Binary und Verb erlaubt sind und kein Match über Shell-Pipes/Semikolons hinweg passiert. Beim Hinzufügen einer Regel: Eintrag in `RAW_RULES`, mindestens je ein Treffer- und ein Negativ-Test im `tests`-Modul. `id`-Slugs sind stabil — sie tauchen in den Block-Meldungen auf.

**Alias-Modul** (`src/aliases.rs`): persistiert eine `BTreeMap<command, Vec<alias>>` als JSON in `~/.config/rsh/aliases.json` (respektiert `XDG_CONFIG_HOME`). `detect_in_path()` erkennt Aliase über `std::fs::canonicalize()`-Vergleich aller ausführbaren PATH-Einträge mit dem Ziel-Binary — fängt Symlinks und Hardlinks, **nicht** Wrapper-Skripte oder umbenannte Kopien.

**Exit-Code-Contract**: Nur 0 (durchlassen) und 2 (blockieren, Meldung in stderr). Andere Exit-Codes vermeiden, weil Claude Code 1 als "Hook-Fehler" interpretiert, was Verhalten je nach Version anders ist als "explizit blockiert".

## Edition

`Cargo.toml` nutzt `edition = "2024"` (von `cargo init` gesetzt). Erfordert einen entsprechend aktuellen Rust-Toolchain — installiert via `rustup` (siehe `~/.cargo/env`).
