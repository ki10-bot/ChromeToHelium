# ChromeToHelium

**1:1 Cookie-Migration von Google Chrome nach Helium Browser unter Windows 10/11.**

Ein Doppelklick genügt: Das Tool liest alle Cookies aus allen Chrome-Profilen,
entschlüsselt sie mit Chromes eigenem Schlüssel, verschlüsselt sie mit Heliums
Schlüssel neu und schreibt sie in Heliums Cookie-Datenbanken – inklusive
Backup, Verifizierung und Bericht. Keine Installation, keine Konfiguration,
keine Kommandozeile.

> Windows-Version des macOS-Tools
> [ArcToHelium](https://github.com/ki10-bot/ArcToHelium) (ki10-bot).

---

## Schnellstart

1. **ZIP herunterladen und entpacken** (z. B. auf dem Desktop).
2. **`ChromeToHelium.bat` doppelklicken.**
3. Fertig. Helium startet automatisch neu – alle Chrome-Cookies sind da.

Das war's. Chrome darf dabei offen bleiben, Helium wird vom Tool geschlossen
und danach neu gestartet.

### Voraussetzungen

- **Windows 10 oder 11** (64 Bit)
- **Google Chrome** installiert und mindestens einmal gestartet
- **Helium Browser** installiert und mindestens einmal gestartet
- **Python 3.10 oder neuer** von <https://www.python.org/downloads/>
  (bei der Installation „Add python.exe to PATH“ anhaken).
  Mehr ist nicht nötig – das Tool nutzt ausschließlich die
  Python-Standardbibliothek, keine pip-Pakete.

---

## Was das Tool tut

1. **Helium wird geschlossen** (Chrome bleibt offen). Helium erkennt die
   Migration sonst nicht bzw. überschreibt sie beim Beenden.
2. **Vollständiges Backup** aller betroffenen Helium- und Chrome-Datenbanken
   (inkl. WAL/SHM-Dateien) nach
   `%LOCALAPPDATA%\ChromeToHelium\Backups\<Datum-Uhrzeit>\` – *vor* jeder
   Änderung.
3. **Chrome-Datenbanken werden konsistent gelesen** (SQLite-Backup-API,
   WAL wird automatisch eingespielt). Alle Profile (`Default`, `Profile 1`,
   …) und alle Cookie-Dateien (`Network\Cookies` und `Cookies`) werden
   erfasst.
4. **Entschlüsseln + neu verschlüsseln:** Jede Cookie wird mit dem
   Chrome-Schlüssel aus der `Local State`-Datei (DPAPI, Format **v10**,
   AES-256-GCM) entschlüsselt und mit dem Helium-Schlüssel neu verschlüsselt
   in Heliums Datenbanken eingefügt. Bestehende Helium-Cookies bleiben
   erhalten.
5. **Verifizierung:** Stichproben werden mit dem Helium-Schlüssel
   zurückentschlüsselt und geprüft.
6. **Bericht:** `REPORT.txt` im Backup-Ordner + `last-run.log` in
   `%LOCALAPPDATA%\ChromeToHelium\`. Helium wird neu gestartet.

### Details

- **Alle Zeilen werden übernommen** – auch abgelaufene Cookies und
  Session-Cookies. Session-Cookies (`is_persistent = 0`) werden als
  persistent markiert, damit Chromium sie nicht beim nächsten Start löscht.
- **Alle 20 kanonischen Felder** bleiben erhalten (Host, Pfad, Secure,
  HttpOnly, SameSite, Ablaufdatum, Priorität, …).
- **Idempotent:** Mehrfach ausführen ist harmlos – vorhandene Cookies werden
  ersetzt, nicht dupliziert.
- **Schlüssel-Cache:** Entschlüsselte Schlüssel werden DPAPI-geschützt in
  `%LOCALAPPDATA%\ChromeToHelium\key-cache.json` zwischengespeichert, damit
  Folgeläufe keinen DPAPI-Aufruf brauchen. Sie werden vor jeder Verwendung
  gegen echte Cookies geprüft.
- **Helium wird über seinen Ausführungspfad erkannt** (Helium heißt intern
  ebenfalls `chrome.exe`) – Chrome wird niemals geschlossen.

---

## Backup wiederherstellen

Einfach **`Restore-Backup.bat` doppelklicken**. Das Tool nimmt automatisch
das neueste Backup und stellt Heliums Cookie-Datenbanken exakt wieder her
(inklusive WAL/SHM-Behandlung, damit kein alter Stand zurückkehrt).

---

## Chrome 127+ / v20 (App-Bound Encryption)

Seit **Chrome 127** verschlüsselt Chrome neue Cookies mit
**App-Bound Encryption** (Format-Präfix `v20`). Der v20-Schlüssel ist
zusätzlich mit dem **SYSTEM-DPAPI-Schlüssel** geschützt und kann von einem
normalen Benutzerprozess **nicht** entschlüsselt werden – dafür wäre
SYSTEM-Zugriff (z. B. über Chromes Elevation Service) nötig.

**Was das Tool damit macht:**

- Alle **v10-Cookies** werden vollständig migriert.
- **v20-Cookies werden übersprungen** und im Bericht transparent mit Anzahl
  ausgewiesen (`v20 uebersprungen : N`) – es werden keine korrupten oder
  leeren Cookies geschrieben.
- Helium selbst nutzt v10, daher sind Helium-Cookies immer migrierbar.

**Optional – v20 für neue Cookies deaktivieren** (nur, wenn du das willst;
wirkt nur für *neue* Cookies, bestehende v20-Cookies bleiben v20):

1. Als Administrator die Eingabeaufforderung öffnen.
2. Diesen Befehl ausführen:

   ```bat
   reg add "HKLM\Software\Policies\Google\Chrome" /v ApplicationBoundEncryptionEnabled /t REG_DWORD /d 0 /f
   ```

3. Chrome vollständig beenden und neu starten.
4. `ChromeToHelium.bat` erneut ausführen – neue Cookies sind dann wieder
   als v10 migrierbar.

---

## Häufige Probleme

| Symptom | Ursache & Lösung |
|---|---|
| „Python wurde nicht gefunden“ | Python installieren (siehe Voraussetzungen) und „Add python.exe to PATH“ anhaken. |
| „Chrome-Profilordner nicht gefunden“ | Chrome einmal starten, dann Tool erneut ausführen. |
| „Kein …-Schlüssel in der Local State gefunden“ | Chrome bzw. Helium einmal starten und anmelden, dann erneut versuchen. |
| „nur ein v20/App-Bound-Schlüssel gefunden“ | Chrome nutzt ausschließlich v20. Siehe Abschnitt „Chrome 127+ / v20“. |
| Helium startet nicht automatisch | Helium einfach selbst öffnen – die Cookies sind bereits geschrieben. |
| Cookies fehlen in Helium | Bericht (`REPORT.txt`) prüfen: Steht dort eine v20-Anzahl? Dann siehe v20-Abschnitt. |

---

## Projektstruktur

```text
ChromeToHelium.bat     Doppelklick-Launcher (Migration)
Restore-Backup.bat     Doppelklick-Launcher (Wiederherstellung)
ChromeToHelium.py      Engine (reine Python-Standardbibliothek)
README.md              Diese Datei
LICENSE                MIT-Lizenz
src/
  engine.py            Engine-Quelle (wird beim Bau nach ChromeToHelium.py kopiert)
  tests/
    test_engine.py     Test-Suite (Krypto-Vektoren, End-to-End, Restore)
build.py               Baut das Release-ZIP (inkl. Testlauf)
```

### Tests ausführen

```bat
python -m unittest discover -s src\tests -v
```

Die Tests laufen auch unter Linux (per `C2H_*`-Umgebungsvariablen, die nur
für Tests gedacht sind) und prüfen u. a. die AES-Vektoren gegen FIPS-197 /
NIST / OpenSSL / Node.js sowie eine komplette Migration mit gefakten
Profilen inklusive Backup, Verifizierung und Restore.

### Release bauen

```bat
python build.py
```

Erzeugt `ChromeToHelium-Windows.zip` mit allen Dateien zum Entpacken und
Doppelklicken.

---

## Lizenz

MIT – siehe [LICENSE](LICENSE).
