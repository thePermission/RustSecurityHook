# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Projekt

`rsh` (Rust Security Hook) ist ein Single-Binary CLI, das als Claude Code **PreToolUse-Hook** registriert wird und jeden geplanten `Bash`-Tool-Call gegen eine Blacklist regulärer Ausdrücke prüft. Trifft eine Regel, wird der Aufruf mit Exit-Code 2 und einer stderr-Begründung blockiert — Claude Code interpretiert das als "Tool-Call verweigert" und gibt die Meldung an das Modell zurück.

Inspiration ist die Hook-/Init-Mechanik von [rtk-ai/rtk](https://github.com/rtk-ai/rtk), aber `rsh` ist bewusst minimal: nur Blocking, kein Rewriting, kein Proxying.

**Status der Blacklist**: aktuell leer. Regeln werden bewusst vom Nutzer manuell ergänzt — `RAW_RULES` in `src/blacklist.rs` ist absichtlich nicht mit Defaults vorgefüllt.

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
| `list` | `rsh list` (alias `rules`) | Listet alle in `RAW_RULES` konfigurierten Regeln (id, reason, pattern) |
| `help` | `rsh help` / `-h` / `--help` | Usage-Übersicht |

Hook-Input-Schema (Claude Code PreToolUse-Event): JSON mit mindestens `tool_name` (string) und `tool_input` (object). Für den `Bash`-Tool steckt der auszuführende Befehl in `tool_input.command`. Bei anderen Tool-Namen oder leerem/ungültigem stdin lässt `rsh` den Call durchgehen (Exit 0) — Fail-Open ist Absicht, damit ein Crash im Hook nicht die ganze Session lahmlegt.

**Blacklist-Modul** (`src/blacklist.rs`): zentrale Stelle für neue Regeln. Regeln sind `(id, regex, reason)`-Tripel in `RAW_RULES`, werden bei der ersten Nutzung in eine `LazyLock<Vec<Rule>>` mit vorkompilierten `Regex` überführt. Beim Hinzufügen einer Regel: Eintrag in `RAW_RULES`, zugehöriger Test im `tests`-Modul derselben Datei (positiv: blockiert; negativ: harmlose Variante geht durch). Stabile `id`-Slugs nicht ändern, sobald gesetzt — sie tauchen in den Block-Meldungen auf.

**Exit-Code-Contract**: Nur 0 (durchlassen) und 2 (blockieren, Meldung in stderr). Andere Exit-Codes vermeiden, weil Claude Code 1 als "Hook-Fehler" interpretiert, was Verhalten je nach Version anders ist als "explizit blockiert".

## Edition

`Cargo.toml` nutzt `edition = "2024"` (von `cargo init` gesetzt). Erfordert einen entsprechend aktuellen Rust-Toolchain — installiert via `rustup` (siehe `~/.cargo/env`).
