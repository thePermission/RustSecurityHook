# Design — Tool-weites Deaktivieren von Blacklist-Regeln

**Datum:** 2026-05-24  
**Status:** Approved

## Ziel

Einzelne Regeln lassen sich bereits mit `rsh rule disable <id>` deaktivieren. Dieses Feature ergänzt die Möglichkeit, alle Regeln eines ganzen Tools (z. B. `kubectl`, `glab`) auf einmal zu deaktivieren — ohne jede Regel-ID einzeln zu nennen.

---

## Abschnitt 1: Dateiformat & Speicherung

### Umbenennung

Die bisherige Konfigurationsdatei wird umbenannt:

```
~/.config/rsh/disabled-rules.json  →  ~/.config/rsh/disabled.json
```

Der Inhalt bleibt ein sortiertes JSON-Array von Strings.

### Namensräume im Array

| Eintrag          | Bedeutung                                     |
|------------------|-----------------------------------------------|
| `"k8s-drain"`    | Einzelne Regel-ID (bisheriges Format, unverändert) |
| `"tool:kubectl"` | Alle Blacklist-Regeln mit `bin == "kubectl"` deaktivieren |

### Migration

`disabled::load()` prüft beim ersten Laden:

1. Existiert `disabled.json` bereits → direkt laden, fertig.
2. Existiert `disabled-rules.json` aber noch keine `disabled.json` → `std::fs::rename()` (atomisch auf Unix), dann laden.
3. Keine der beiden Dateien existiert → leere Menge, fertig.

Kein separater Migrationsbefehl, kein User-Interaktion nötig.

---

## Abschnitt 2: CLI-Befehle

Neuer Subbefehl `rsh tool`, strukturell analog zu `rsh rule`:

```
rsh tool disable <bin>   # deaktiviert alle Regeln für das Tool
rsh tool enable <bin>    # aktiviert das Tool wieder
rsh tool list            # zeigt alle bekannten Bins mit Regelanzahl und Status
```

`<bin>` ist der kanonische Binary-Name (`kubectl`, `docker`, `glab`, `helm`, `aws`, `gh`, `git`, …).

**Validierung:** `rsh tool disable <bin>` prüft, ob für den angegebenen Namen Regeln existieren (`blacklist::rules()` gefiltert nach `r.bin == Some(bin)`). Gibt es keine, wird ein Fehler ausgegeben:

```
error: no rules bound to tool 'foobar'
hint: run `rsh tool list` to see all known tools
```

Die bestehenden `rsh rule disable/enable`-Befehle bleiben unverändert.

---

## Abschnitt 3: Runtime-Verhalten

### Blacklist-Check

In `blacklist::check_filtered(command, disabled)` wird die Prüfung erweitert:

```rust
if disabled.contains(rule.id) {
    continue;
}
if let Some(bin) = rule.bin {
    if disabled.contains(&format!("tool:{bin}")) {
        continue;
    }
}
```

### Secret-Regeln

Secret-Regeln (`secrets::check_filtered`) haben kein `bin`-Feld und werden von `rsh tool disable` **nicht** erfasst. Sie bleiben ausschließlich über `rsh rule disable <id>` steuerbar.

### Listenausgabe (`rsh list` / `rsh rule list`)

Eine Kategoriengruppe, deren Regeln alle demselben Bin angehören, erhält `[TOOL DISABLED]` hinter ihrem Kategorietitel, wenn `"tool:<bin>"` in `disabled.json` steht.

Kategorien mit gemischten Bins werden nicht pauschal markiert.

---

## Abschnitt 4: Migration & Tests

### Neue Funktionen in `disabled.rs`

```rust
pub fn add_tool(bin: &str) -> Result<bool>    // schreibt "tool:<bin>"
pub fn remove_tool(bin: &str) -> Result<bool> // entfernt "tool:<bin>"
```

Beide delegieren intern an die bestehenden `add()` / `remove()` Funktionen.

### Testfälle

- **Migration:** `disabled-rules.json` vorhanden → wird zu `disabled.json` umbenannt, Inhalt identisch
- **Schreiben:** `rsh tool disable kubectl` schreibt `"tool:kubectl"` in `disabled.json`
- **Runtime-Block:** `check_filtered` überspringt alle kubectl-Regeln wenn `"tool:kubectl"` gesetzt
- **Runtime-Allow:** `check_filtered` blockiert weiterhin nicht-kubectl-Regeln unverändert
- **Listausgabe:** kubectl-Kategorie wird mit `[TOOL DISABLED]` markiert
- **Validierung:** Unbekannter Bin-Name → Fehler mit Hinweis auf `rsh tool list`
- **Idempotenz:** `rsh tool disable kubectl` zweimal → kein Fehler, keine doppelten Einträge
- **Koexistenz:** `"tool:kubectl"` und eine einzelne `"k8s-drain"`-Deaktivierung gleichzeitig in der Datei → beide wirken korrekt
