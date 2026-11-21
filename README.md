# ChromeToHelium

Move all cookies from Google Chrome to Helium Browser on Windows — one-to-one:
every profile, every row, session and expired cookies included. Double-click
one file, no input, no install. Automatic backup + restore.

The tool reads all cookies from all Chrome profiles, decrypts them with
Chrome's own key, re-encrypts them with Helium's key and writes them into
Helium's cookie databases — including backup, verification and report. No
installation, no configuration, no command line.

> Windows version of the macOS tool
> [ArcToHelium](https://github.com/ki10-bot/ArcToHelium) (ki10-bot).

---

## Quick start

1. **Download and unzip** (e.g. to your Desktop).
2. **Double-click `ChromeToHelium.bat`.**
3. Done. Helium restarts automatically — all Chrome cookies are there.

That's it. Chrome may stay open during the run; Helium is closed by the tool
and restarted afterwards.

### Requirements

- **Windows 10 or 11** (64-bit)
- **Google Chrome** installed and started at least once
- **Helium Browser** installed and started at least once
- **Python 3.10 or newer** from <https://www.python.org/downloads/>
  (tick “Add python.exe to PATH” during installation).
  Nothing else is needed — the tool uses only the Python standard library,
  no pip packages.

---

## What the tool does

1. **Helium is closed** (Chrome stays open). Otherwise Helium would not pick
   up the migration or would overwrite it on exit.
2. **Full backup** of all affected Helium and Chrome databases (including
   WAL/SHM files) to
   `%LOCALAPPDATA%\ChromeToHelium\Backups\<date-time>\` — *before* any
   change.
3. **Chrome databases are read consistently** (SQLite backup API, WAL is
   replayed automatically). All profiles (`Default`, `Profile 1`, …) and
   all cookie files (`Network\Cookies` and `Cookies`) are covered.
4. **Decrypt + re-encrypt:** every cookie is decrypted with the Chrome key
   from the `Local State` file (DPAPI, **v10** format, AES-256-GCM) and
   re-encrypted with the Helium key into Helium's databases. Existing
   Helium cookies are preserved.
5. **Verification:** samples are decrypted back with the Helium key and
   checked.
6. **Report:** `REPORT.txt` in the backup folder + `last-run.log` in
   `%LOCALAPPDATA%\ChromeToHelium\`. Helium is restarted.

### Details

- **All rows are carried over** — including expired cookies and session
  cookies. Session cookies (`is_persistent = 0`) are marked persistent so
  Chromium does not delete them at the next start.
- **All 20 canonical fields** are preserved (host, path, secure, HttpOnly,
  SameSite, expiry, priority, …).
- **Idempotent:** running it multiple times is harmless — existing cookies
  are replaced, not duplicated.
- **Key cache:** decrypted keys are cached DPAPI-protected in
  `%LOCALAPPDATA%\ChromeToHelium\key-cache.json` so follow-up runs need no
  DPAPI call. They are validated against real cookies before every use.
- **Helium is detected by its executable path** (Helium is internally also
  named `chrome.exe`) — Chrome is never closed.

---

## Restore a backup

Simply **double-click `Restore-Backup.bat`**. The tool automatically picks
the newest backup and restores Helium's cookie databases exactly (including
WAL/SHM handling, so no old state comes back).

---

## Chrome 127+ / v20 (App-Bound Encryption)

Since **Chrome 127**, Chrome encrypts new cookies with **App-Bound
Encryption** (format prefix `v20`). The v20 key is additionally protected
with the **SYSTEM DPAPI key** and cannot be decrypted by a normal user
process — SYSTEM access (e.g. via Chrome's elevation service) would be
required.

**What the tool does about it:**

- All **v10 cookies** are migrated completely.
- **v20 cookies are skipped** and transparently reported with their count
  (`v20 skipped : N`) — no corrupt or empty cookies are written.
- Helium itself uses v10, so Helium cookies are always migratable.

**Optional — disable v20 for new cookies** (only if you want to; affects
*new* cookies only, existing v20 cookies stay v20):

1. Open the Command Prompt as Administrator.
2. Run:

   ```bat
   reg add "HKLM\Software\Policies\Google\Chrome" /v ApplicationBoundEncryptionEnabled /t REG_DWORD /d 0 /f
   ```

3. Fully quit Chrome and restart it.
4. Run `ChromeToHelium.bat` again — new cookies are then migratable as v10.

---

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| “Python was not found” | Install Python (see Requirements) and tick “Add python.exe to PATH”. |
| “Chrome profile folder not found” | Start Chrome once, then run the tool again. |
| “No … key found in Local State” | Start Chrome / Helium once and sign in, then try again. |
| “Only a v20/App-Bound key was found” | Chrome uses v20 exclusively. See “Chrome 127+ / v20”. |
| Helium does not start automatically | Just open Helium yourself — the cookies are already written. |
| Cookies missing in Helium | Check the report (`REPORT.txt`): is there a v20 count? Then see the v20 section. |

---

## Project structure

```text
ChromeToHelium.bat     Double-click launcher (migration)
Restore-Backup.bat     Double-click launcher (restore)
ChromeToHelium.py      Engine (pure Python standard library)
README.md              This file
LICENSE                MIT license
src/
  engine.py            Engine source (copied to ChromeToHelium.py at build time)
  tests/
    test_engine.py     Test suite (crypto vectors, end-to-end, restore)
build.py               Builds the release ZIP (including test run)
```

### Run the tests

```bat
python -m unittest discover -s src\tests -v
```

The tests also run on Linux (via `C2H_*` environment variables, meant for
tests only) and cover, among other things, the AES vectors against
FIPS-197 / NIST / OpenSSL / Node.js plus a complete migration with fake
profiles including backup, verification and restore.

### Build the release

```bat
python build.py
```

Creates `ChromeToHelium-Windows.zip` with all files for unzip-and-double-click.

---

## License

MIT — see [LICENSE](LICENSE).
