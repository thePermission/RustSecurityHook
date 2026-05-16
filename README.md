# rsh – Rust Security Hook

Ein schlanker Claude-Code-`PreToolUse`-Hook. Vor jedem `Bash`-Tool-Call prüft `rsh` den Befehl gegen eine Blacklist und blockiert ihn bei Treffer mit einer Begründung. Claude Code wertet das als "Tool-Call verweigert" und reicht die Meldung ans Modell zurück.

Aktuell mitgeliefert: ein kleiner Satz Regeln für destruktive `kubectl`-Operationen (`delete namespace`, `delete --all`, `delete crd`, force-delete). Welche Regeln aktiv sind, kannst du jederzeit mit `rsh list` einsehen.

## Installation

### One-Liner (Linux / macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh
```

Das Skript lädt ein fertiges Binary aus dem [GitHub-Release](https://github.com/thePermission/RustSecurityHook/releases) für deine Plattform und legt es unter `~/.local/bin/rsh` ab. Keine Build-Werkzeuge oder Rust-Toolchain nötig.

Unterstützte Plattformen:

| OS | Architektur |
|----|-------------|
| Linux | x86_64, aarch64 |
| macOS | x86_64, Apple Silicon (aarch64) |

Optionale Env-Vars:

| Variable | Wirkung |
|----------|---------|
| `RSH_VERSION` | Bestimmten Release-Tag installieren (z.B. `v0.2.0`); Default ist das neueste Release |
| `RSH_INSTALL_DIR` | Anderen Zielordner verwenden (Default: `~/.local/bin`) |

Stelle sicher, dass dein Zielordner in `$PATH` liegt — das Skript warnt dich, falls nicht.

### Verifizieren

```sh
rsh --version
rsh --help
```

## Als Claude-Code-Hook registrieren

Einmal nach der Installation ausführen:

```sh
rsh init -g          # global in ~/.claude/settings.json
# oder projektlokal:
rsh init             # in ./.claude/settings.json des aktuellen Verzeichnisses
```

`init` ist idempotent (mehrfache Ausführung erzeugt keine Dubletten) und scannt im Anschluss automatisch deinen `$PATH` nach bekannten Aliasen für `kubectl` und andere Regel-Binaries.

Zum Entfernen einfach den entsprechenden `PreToolUse`-Eintrag aus der `settings.json` löschen.

## Benutzung

`rsh` wird primär automatisch von Claude Code aufgerufen — nach `rsh init` ist nichts weiter nötig. Für manuelle Inspektion:

```sh
rsh list                          # alle Regeln und Aliase übersichtlich anzeigen
rsh check "kubectl delete ns prod"  # einen literalen Befehl gegen die Blacklist prüfen
```

Exit-Codes (relevant für den Hook-Modus):

| Code | Bedeutung |
|------|-----------|
| `0`  | Befehl ist erlaubt |
| `2`  | Befehl wurde blockiert; Begründung steht auf stderr |

## Aliase verwalten

Die Blacklist erkennt nicht nur die exakten Binary-Namen (z.B. `kubectl`), sondern auch alle registrierten Aliase. Aliase liegen in `~/.config/rsh/aliases.json`.

```sh
rsh alias kubectl k          # manuell: "k" zeigt auf kubectl
rsh detect-aliases           # automatisch: scannt $PATH nach allen Regel-Binaries
rsh detect-aliases helm      # gezielter Scan für ein bestimmtes Tool
```

**Was automatisch erkannt wird:** Symlinks und Hardlinks im `$PATH`, deren `realpath()` auf dasselbe Binary auflöst.

**Was nicht erkannt wird:** Wrapper-Skripte, Shell-Aliase aus `.bashrc`/`.zshrc` (werden in `bash -c` ohnehin nicht expandiert) und umbenannte Kopien des Binaries. Eine reine Textblacklist kann determinierte Umgehung nicht verhindern.

Mit `rsh list` siehst du, welche Aliase aktiv in die Regeln eingebaut werden.

## Befehlsübersicht

```text
rsh                          Hook-Modus (von Claude Code aufgerufen)
rsh init [-g|--global]       Hook in settings.json eintragen
rsh check "<command>"        Blacklist gegen einen Befehl prüfen
rsh list                     Alle Regeln und Aliase anzeigen
rsh alias <cmd> <alias>      Alias eintragen
rsh detect-aliases [cmd]     Aliase automatisch erkennen
rsh help    (-h, --help)     Hilfe anzeigen
rsh version (-v, --version)  Version anzeigen
```

## Lizenz

Apache License 2.0 — siehe [LICENSE](LICENSE).
