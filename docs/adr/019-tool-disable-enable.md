# ADR 019 — Tool-weites Deaktivieren von Blacklist-Regeln

**Date:** 2026-05-24
**Status:** Accepted

## Context

`rsh rule disable <id>` erlaubt das gezielte Deaktivieren einzelner Regeln (ADR 008).
Bei Tools wie `kubectl` oder `glab`, die viele Regeln bündeln, ist es unpraktisch, jede
Regel einzeln zu deaktivieren — z. B. für einen Maintenance-Window auf einem
Entwicklungscluster, bei dem alle kubectl-Operationen temporär erlaubt sein sollen.

## Decision

`rsh tool disable <bin>` / `rsh tool enable <bin>` deaktiviert bzw. reaktiviert alle
Blacklist-Regeln für ein bestimmtes Binary auf einmal. Das Ergebnis wird als
`"tool:<bin>"`-Eintrag in der gemeinsamen Konfigurationsdatei `~/.config/rsh/disabled.json`
gespeichert. Die bisherige Datei `disabled-rules.json` wird beim ersten Zugriff via
`std::fs::rename` automatisch migriert — kein manueller Eingriff nötig.

`check_filtered` prüft nach der Regel-ID-Prüfung zusätzlich `"tool:<bin>"` für jede
Regel mit gebundenem Binary. Regeln ohne `bin` (z. B. Secret-Regeln) sind von
`rsh tool disable` nicht betroffen.

Eine neue Selbstschutz-Regel `rsh-protect-tool-disable` blockiert Bash-Aufrufe von
`rsh tool disable` aus dem Hook heraus — analog zu `rsh-protect-disable` (ADR 009).

In `rsh list` und `rsh rule list` erhält eine Kategoriengruppe, deren Regeln alle
demselben Binary zugeordnet sind, den Marker `[TOOL DISABLED]` hinter dem Kategorietitel.

## Alternatives Considered

- **Separate `disabled-tools.json`:** Abgelehnt — ein zweites Dateiformat erhöht die
  kognitive Last und erfordert einen zweiten Lade-Pfad ohne nennenswerten Vorteil.
- **Expansion auf Einzelregeln beim Disable-Aufruf:** Abgelehnt — bei einem
  rsh-Upgrade mit neuen Regeln für dasselbe Binary wären diese nicht automatisch
  deaktiviert. Das `"tool:"`-Präfix ist zukunftssicher.

## Consequences

- `rsh tool disable kubectl` schreibt einen einzigen Eintrag statt dutzender Einzel-IDs.
- Neue kubectl-Regeln in zukünftigen rsh-Versionen werden automatisch durch einen
  bestehenden `"tool:kubectl"`-Eintrag deaktiviert.
- Die bestehende Datei `disabled-rules.json` wird bei erstem Zugriff nach dem Upgrade
  still zu `disabled.json` umbenannt.
- Secret-Regeln (kein `bin`-Feld) sind weiterhin nur per `rsh rule disable <id>`
  steuerbar.
