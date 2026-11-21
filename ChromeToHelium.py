#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chrome -> Helium: 1:1 Cookie-Migration fuer Windows 10/11.

Liest alle Cookies aus allen Chrome-Profilen, entschluesselt sie mit dem
Chrome-Schluessel aus der "Local State"-Datei (DPAPI, Format v10),
verschluesselt sie mit dem Helium-Schluessel neu und schreibt sie in
Heliums eigene Cookie-Datenbanken.

Windows-Version des macOS-Tools "ArcToHelium" (ki10-bot/ArcToHelium).
Nur Python-Standardbibliothek noetig. Keine pip-Pakete, keine Installation.

Ablauf (wie im Original):
  1. Helium wird geschlossen (Chrome bleibt offen).
  2. Vollstaendiges Backup aller betroffenen Helium-Datenbanken.
  3. Chrome-Datenbanken werden per SQLite-Backup-API gelesen (WAL wird
     automatisch eingespielt), Chrome darf offen bleiben.
  4. Zeilen werden entschluesselt + neu verschluesselt und in Helium
     eingefuegt (bestehende Helium-Cookies bleiben erhalten).
  5. Stichproben werden mit dem Helium-Schluessel zurueckentschluesselt.
  6. Bericht wird geschrieben, Helium wird neu gestartet.

Hinweis zu Chrome 127+ (App-Bound Encryption / v20):
  Neue Chrome-Cookies werden seit Chrome 127 mit "v20" verschluesselt.
  Der v20-Schluessel ist zusaetzlich mit dem SYSTEM-DPAPI-Schluessel
  geschuetzt und kann von einem normalen Benutzerprozess nicht
  entschluesselt werden (dafuer waere SYSTEM-Zugriff noetig).
  Dieses Tool migriert alle v10-Cookies vollstaendig und meldet
  v20-Cookies transparent als uebersprungen (mit Anzahl im Bericht).
  Helium selbst nutzt v10, daher sind Helium-Cookies immer migrierbar.
  Details: README.md, Abschnitt "Chrome 127+ / v20".

Aufruf:
  python engine.py            Migration ausfuehren
  python engine.py --restore  Letztes Backup wiederherstellen
  python engine.py --help     Hilfe anzeigen

Umgebungsvariablen (nur fuer Tests, normal nicht noetig):
  C2H_LOCALAPPDATA, C2H_CHROME_ROOT, C2H_HELIUM_ROOT,
  C2H_SKIP_DPAPI, C2H_SKIP_QUIT, C2H_SKIP_RELAUNCH,
  C2H_FORCE_PERSISTENT, C2H_ALLOW_NON_WINDOWS
"""
from __future__ import annotations

import base64
import ctypes
import datetime as _dt
import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Umgebung / Testbarkeit (Standardwerte bleiben im Normalbetrieb unberuehrt)
# ---------------------------------------------------------------------------


def env(name: str, default: str = "") -> str:
    return os.environ.get("C2H_" + name, default)


def flag(name: str) -> bool:
    return env(name, "") not in ("", "0", "false", "no")


def localappdata() -> str:
    p = env("LOCALAPPDATA") or os.environ.get("LOCALAPPDATA", "")
    if p:
        return os.path.abspath(p)
    home = os.path.expanduser("~")
    return os.path.join(home, "AppData", "Local")


def userprofile() -> str:
    return os.path.abspath(os.environ.get("USERPROFILE", os.path.expanduser("~")))


SUPPORT = os.path.join(localappdata(), "ChromeToHelium")
LOGFILE = os.path.join(SUPPORT, "last-run.log")
CACHEFILE = os.path.join(SUPPORT, "key-cache.json")

# Sollen Session-Cookies (is_persistent = 0) als persistent markiert werden?
# Chromium loescht diese sonst beim naechsten Start. Standard: ja.
FORCE_PERSISTENT = env("FORCE_PERSISTENT", "1") not in ("0", "false", "no")

# Spalten, die Helium zusaetzlich haben kann und die NOT NULL ohne DEFAULT sind.
COLUMN_DEFAULTS = {
    "top_frame_site_key": "",
    "value": "",
    "path": "/",
    "host_key": "",
    "name": "",
    "samesite": -1,
    "source_port": -1,
    "source_scheme": 0,
    "source_type": 0,
    "has_cross_site_ancestor": 0,
    "priority": 1,
    "has_expires": 1,
    "is_persistent": 1,
    "last_update_utc": 0,
    "creation_utc": 0,
    "last_access_utc": 0,
    "expires_utc": 0,
    "is_secure": 0,
    "is_httponly": 0,
    "encrypted_value": b"",
}

_LOG: list[str] = []


def log(msg: str = "") -> None:
    print(msg, flush=True)
    _LOG.append(msg)


def warn(msg: str) -> None:
    log("  ! " + msg)


def ok(msg: str) -> None:
    log("  ok  " + msg)


class Fatal(Exception):
    pass


# ---------------------------------------------------------------------------
# AES in purem Python (Fallback, wenn keine Crypto-Bibliothek vorhanden ist)
# AES-128/192/256, CBC + GCM. Getestet gegen FIPS-197 / NIST-Vektoren.
# ---------------------------------------------------------------------------
def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _gpow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gmul(r, a)
        a = _gmul(a, a)
        n >>= 1
    return r


def _make_sboxes():
    sbox = []
    for a in range(256):
        inv = _gpow(a, 254) if a else 0
        s = inv
        for sh in (1, 2, 3, 4):
            s ^= ((inv << sh) | (inv >> (8 - sh))) & 0xFF
        sbox.append(s ^ 0x63)
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _make_sboxes()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]

# Multiplikationstabellen fuer MixColumns (schneller als _gmul in der Schleife)
MUL2 = [_gmul(x, 2) for x in range(256)]
MUL3 = [_gmul(x, 3) for x in range(256)]
MUL9 = [_gmul(x, 9) for x in range(256)]
MUL11 = [_gmul(x, 11) for x in range(256)]
MUL13 = [_gmul(x, 13) for x in range(256)]
MUL14 = [_gmul(x, 14) for x in range(256)]


class AES:
    """AES-128/192/256 mit ECB-Blockoperationen; CBC/GCM werden darauf aufgebaut."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES-Schluessel muss 16, 24 oder 32 Bytes lang sein")
        nk = len(key) // 4
        self.nr = nk + 6
        w = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
        for i in range(nk, 4 * (self.nr + 1)):
            t = w[i - 1][:]
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [SBOX[x] for x in t]
                t[0] ^= RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                t = [SBOX[x] for x in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        self.rk = []
        for r in range(self.nr + 1):
            self.rk.append(bytes(sum((w[r * 4 + c] for c in range(4)), [])))

    @staticmethod
    def _shift_rows(s: bytearray, inverse: bool = False) -> bytearray:
        out = bytearray(16)
        for c in range(4):
            for r in range(4):
                src_c = (c - r) % 4 if inverse else (c + r) % 4
                out[4 * c + r] = s[4 * src_c + r]
        return out

    @staticmethod
    def _mix_columns(s: bytearray, inverse: bool = False) -> bytearray:
        out = bytearray(16)
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            if inverse:
                out[4 * c + 0] = MUL14[a[0]] ^ MUL11[a[1]] ^ MUL13[a[2]] ^ MUL9[a[3]]
                out[4 * c + 1] = MUL9[a[0]] ^ MUL14[a[1]] ^ MUL11[a[2]] ^ MUL13[a[3]]
                out[4 * c + 2] = MUL13[a[0]] ^ MUL9[a[1]] ^ MUL14[a[2]] ^ MUL11[a[3]]
                out[4 * c + 3] = MUL11[a[0]] ^ MUL13[a[1]] ^ MUL9[a[2]] ^ MUL14[a[3]]
            else:
                out[4 * c + 0] = MUL2[a[0]] ^ MUL3[a[1]] ^ a[2] ^ a[3]
                out[4 * c + 1] = a[0] ^ MUL2[a[1]] ^ MUL3[a[2]] ^ a[3]
                out[4 * c + 2] = a[0] ^ a[1] ^ MUL2[a[2]] ^ MUL3[a[3]]
                out[4 * c + 3] = MUL3[a[0]] ^ a[1] ^ a[2] ^ MUL2[a[3]]
        return out

    @staticmethod
    def _add_round_key(s: bytearray, rk: bytes) -> bytearray:
        return bytearray(s[i] ^ rk[i] for i in range(16))

    def encrypt_block(self, block: bytes) -> bytes:
        s = self._add_round_key(bytearray(block), self.rk[0])
        for r in range(1, self.nr + 1):
            s = bytearray(SBOX[b] for b in s)
            s = self._shift_rows(s)
            if r != self.nr:
                s = self._mix_columns(s)
            s = self._add_round_key(s, self.rk[r])
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = self._add_round_key(bytearray(block), self.rk[self.nr])
        for r in range(self.nr - 1, -1, -1):
            s = self._shift_rows(s, inverse=True)
            s = bytearray(INV_SBOX[b] for b in s)
            s = self._add_round_key(s, self.rk[r])
            if r != 0:
                s = self._mix_columns(s, inverse=True)
        return bytes(s)


IV = b" " * 16  # Chromium nutzt 16 Leerzeichen als IV (CBC)


def _pkcs7(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _unpkcs7(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def _aes_cbc_encrypt_pure(plain: bytes, key: bytes) -> bytes:
    cipher = AES(key)
    data = _pkcs7(plain)
    prev = IV
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = cipher.encrypt_block(block)
        out += prev
    return bytes(out)


def _aes_cbc_decrypt_pure(data: bytes, key: bytes) -> bytes | None:
    if len(data) < 16 or len(data) % 16:
        return None
    cipher = AES(key)
    prev = IV
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        dec = cipher.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _unpkcs7(bytes(out))


def _ghash(h: bytes, data: bytes) -> bytes:
    """GHASH ueber data (Laenge muss Vielfaches von 16 sein)."""
    x = 0
    hint = int.from_bytes(h, "big")
    for i in range(0, len(data), 16):
        x ^= int.from_bytes(data[i:i + 16], "big")
        # Polynom-Multiplikation in GF(2^128)
        z = 0
        v = hint
        for j in range(128):
            if (x >> (127 - j)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
        x = z
    return x.to_bytes(16, "big")


def _gctr(cipher: AES, j0: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = int.from_bytes(j0, "big")
    for i in range(0, len(data), 16):
        counter = (counter & ~0xFFFFFFFF) | (((counter & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)
        ks = cipher.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _aes_gcm_encrypt_pure(plain: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    cipher = AES(key)
    h = cipher.encrypt_block(b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = _gctr(cipher, j0, plain)
    # GHASH ueber (kein AAD) || pad || ct || pad || len(AAD) || len(ct)
    s = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    s += (0).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    tag_mask = cipher.encrypt_block(j0)
    tag = bytes(a ^ b for a, b in zip(_ghash(h, s), tag_mask))
    return ct, tag


def _aes_gcm_decrypt_pure(ct: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes | None:
    cipher = AES(key)
    h = cipher.encrypt_block(b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    s = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    s += (0).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    tag_mask = cipher.encrypt_block(j0)
    expected = bytes(a ^ b for a, b in zip(_ghash(h, s), tag_mask))
    if expected != tag:
        return None
    return _gctr(cipher, j0, ct)


# --- Schnelle Pfade ueber installierte Bibliotheken (optional) -------------
try:  # cryptography
    from cryptography.hazmat.primitives.ciphers import Cipher as _LibCipher, algorithms as _LibAlg, modes as _LibModes  # type: ignore
    from cryptography.hazmat.backends import default_backend as _LibBackend  # type: ignore

    def _aes_cbc_encrypt_lib(plain: bytes, key: bytes) -> bytes:
        enc = _LibCipher(_LibAlg.AES(key), _LibModes.CBC(IV), backend=_LibBackend()).encryptor()
        return enc.update(_pkcs7(plain)) + enc.finalize()

    def _aes_cbc_decrypt_lib(data: bytes, key: bytes) -> bytes | None:
        if len(data) < 16 or len(data) % 16:
            return None
        dec = _LibCipher(_LibAlg.AES(key), _LibModes.CBC(IV), backend=_LibBackend()).decryptor()
        return _unpkcs7(dec.update(data) + dec.finalize())

    def _aes_gcm_encrypt_lib(plain: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM  # type: ignore
        out = _AESGCM(key).encrypt(nonce, plain, None)
        return out[:-16], out[-16:]

    def _aes_gcm_decrypt_lib(ct: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes | None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM  # type: ignore
        try:
            return _AESGCM(key).decrypt(nonce, ct + tag, None)
        except Exception:
            return None

    _BACKEND = "cryptography"
except Exception:
    try:  # pycryptodome
        from Crypto.Cipher import AES as _PC_AES  # type: ignore

        def _aes_cbc_encrypt_lib(plain: bytes, key: bytes) -> bytes:
            return _PC_AES.new(key, _PC_AES.MODE_CBC, IV).encrypt(_pkcs7(plain))

        def _aes_cbc_decrypt_lib(data: bytes, key: bytes) -> bytes | None:
            if len(data) < 16 or len(data) % 16:
                return None
            return _unpkcs7(_PC_AES.new(key, _PC_AES.MODE_CBC, IV).decrypt(data))

        def _aes_gcm_encrypt_lib(plain: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
            c = _PC_AES.new(key, _PC_AES.MODE_GCM, nonce=nonce)
            ct, tag = c.encrypt_and_digest(plain)
            return ct, tag

        def _aes_gcm_decrypt_lib(ct: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes | None:
            try:
                return _PC_AES.new(key, _PC_AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
            except Exception:
                return None

        _BACKEND = "pycryptodome"
    except Exception:
        _aes_cbc_encrypt_lib = None  # type: ignore
        _aes_cbc_decrypt_lib = None  # type: ignore
        _aes_gcm_encrypt_lib = None  # type: ignore
        _aes_gcm_decrypt_lib = None  # type: ignore
        _BACKEND = "pure-python"


def aes_cbc_encrypt(plain: bytes, key: bytes) -> bytes:
    if _aes_cbc_encrypt_lib is not None:
        return _aes_cbc_encrypt_lib(plain, key)
    return _aes_cbc_encrypt_pure(plain, key)


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes | None:
    if _aes_cbc_decrypt_lib is not None:
        return _aes_cbc_decrypt_lib(data, key)
    return _aes_cbc_decrypt_pure(data, key)


def aes_gcm_encrypt(plain: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    if _aes_gcm_encrypt_lib is not None:
        return _aes_gcm_encrypt_lib(plain, key, nonce)
    return _aes_gcm_encrypt_pure(plain, key, nonce)


def aes_gcm_decrypt(ct: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes | None:
    if _aes_gcm_decrypt_lib is not None:
        return _aes_gcm_decrypt_lib(ct, key, nonce, tag)
    return _aes_gcm_decrypt_pure(ct, key, nonce, tag)


def derive_cbc_key(raw_key: bytes) -> bytes:
    """Windows-CBC-Ableitung: PBKDF2-HMAC-SHA1(Schluessel, 'saltysalt', 1)."""
    return hashlib.pbkdf2_hmac("sha1", raw_key, b"saltysalt", 1, 16)


def host_hash(host_key: str) -> bytes:
    return hashlib.sha256(host_key.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# DPAPI (Windows) ueber ctypes - kein pywin32 noetig
# ---------------------------------------------------------------------------
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi_call(func_name: str, data: bytes) -> bytes:
    if sys.platform != "win32":
        raise Fatal("DPAPI ist nur unter Windows verfuegbar.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _DATA_BLOB(len(data), (ctypes.c_ubyte * len(data)).from_buffer_copy(data))
    out_blob = _DATA_BLOB()
    if func_name == "unprotect":
        func = crypt32.CryptUnprotectData
        func.argtypes = [ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(ctypes.c_void_p),
                         ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_ulong, ctypes.POINTER(_DATA_BLOB)]
        func.restype = ctypes.c_bool
        ok_call = func(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    else:
        func = crypt32.CryptProtectData
        func.argtypes = [ctypes.POINTER(_DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(_DATA_BLOB),
                         ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(_DATA_BLOB)]
        func.restype = ctypes.c_bool
        ok_call = func(ctypes.byref(in_blob), "ChromeToHelium", None, None, None, 0,
                       ctypes.byref(out_blob))
    if not ok_call:
        raise Fatal("DPAPI-Aufruf fehlgeschlagen (%s)." % func_name)
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect(data: bytes) -> bytes:
    return _dpapi_call("unprotect", data)


def dpapi_protect(data: bytes) -> bytes:
    return _dpapi_call("protect", data)


# ---------------------------------------------------------------------------
# Schluessel aus "Local State" laden (Chrome + Helium, Format v10)
# ---------------------------------------------------------------------------
def read_local_state(user_data_root: str) -> dict:
    path = os.path.join(user_data_root, "Local State")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def load_v10_key(user_data_root: str, label: str) -> tuple[bytes | None, bool]:
    """-> (roher v10-Schluessel oder None, True wenn v20/App-Bound vorhanden)."""
    state = read_local_state(user_data_root)
    oscrypt = state.get("os_crypt", {}) if isinstance(state, dict) else {}
    v20_present = bool(oscrypt.get("app_bound_encrypted_key"))
    enc_b64 = oscrypt.get("encrypted_key", "")
    if not enc_b64:
        return None, v20_present
    try:
        raw = base64.b64decode(enc_b64)
    except Exception:
        return None, v20_present
    if raw[:5] == b"DPAPI":
        raw = raw[5:]
    if flag("SKIP_DPAPI"):
        # Nur fuer Tests: Schluessel liegt im Klartext vor (kein DPAPI).
        return raw, v20_present
    try:
        key = dpapi_unprotect(raw)
    except Fatal:
        raise
    except Exception as e:
        raise Fatal(
            "Der %s-Schluessel konnte nicht mit DPAPI entschluesselt werden (%s).\n"
            "  Bitte Chrome/Helium einmal starten und das Tool erneut ausfuehren."
            % (label, e))
    return key, v20_present


def cache_load() -> dict:
    try:
        with open(CACHEFILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for k, v in data.items():
        try:
            blob = base64.b64decode(v)
            if flag("SKIP_DPAPI"):
                out[k] = blob
            else:
                out[k] = dpapi_unprotect(blob)
        except Exception:
            continue
    return out


def cache_save(data: dict) -> None:
    try:
        os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
        payload = {}
        for k, v in data.items():
            if flag("SKIP_DPAPI"):
                payload[k] = base64.b64encode(v).decode("ascii")
            else:
                payload[k] = base64.b64encode(dpapi_protect(v)).decode("ascii")
        tmp = CACHEFILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, CACHEFILE)
    except OSError:
        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Chromium-Cookie-Verschluesselung (v10: GCM modern, CBC historisch)
# ---------------------------------------------------------------------------
def chromium_decrypt_v10(blob: bytes, raw_key: bytes) -> tuple[bytes | None, str | None]:
    """-> (Klartext, Methode 'gcm'/'cbc' oder None)."""
    if not blob or blob[:3] != b"v10" or len(blob) <= 3:
        return None, None
    # Modernes Format: v10 + 12-Byte-Nonce + Ciphertext + 16-Byte-Tag.
    # (Kurze CBC-Werte sind kuerzer als 31 Bytes und fallen hier durch.)
    if len(blob) >= 3 + 12 + 16 and len(raw_key) in (16, 24, 32):
        nonce, ct, tag = blob[3:15], blob[15:-16], blob[-16:]
        plain = aes_gcm_decrypt(ct, raw_key, nonce, tag)
        if plain is not None:
            return plain, "gcm"
    # Historisches CBC-Format (Chrome < 80 / aeltere Chromium-Ableitungen)
    try:
        cbc_key = derive_cbc_key(raw_key)
        plain = aes_cbc_decrypt(blob[3:], cbc_key)
        if plain is not None:
            return plain, "cbc"
    except Exception:
        pass
    return None, None


def chromium_encrypt_v10(plain: bytes, raw_key: bytes, method: str) -> bytes:
    if method == "cbc":
        return b"v10" + aes_cbc_encrypt(plain, derive_cbc_key(raw_key))
    nonce = os.urandom(12)
    ct, tag = aes_gcm_encrypt(plain, raw_key, nonce)
    return b"v10" + nonce + ct + tag


def looks_printable(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:64]
    good = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(sample) > 0.85


# ---------------------------------------------------------------------------
# Windows-Helfer: Pfade, Registry, Prozesse
# ---------------------------------------------------------------------------
def run(cmd, timeout=30, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return None
    except (OSError, ValueError):
        return None


def platform_check() -> None:
    if flag("ALLOW_NON_WINDOWS"):
        return
    if sys.platform != "win32":
        raise Fatal("Dieses Programm laeuft nur unter Windows 10/11.")


def chrome_roots() -> list[str]:
    roots = []
    custom = env("CHROME_ROOT")
    if custom:
        roots.append(custom)
    roots.append(os.path.join(localappdata(), "Google", "Chrome", "User Data"))
    roots.append(os.path.join(localappdata(), "Google", "Chrome for Testing", "User Data"))
    return roots


def helium_exe_candidates() -> list[str]:
    cands = []
    custom = env("HELIUM_EXE")
    if custom:
        cands.append(custom)
    la = localappdata()
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    cands += [
        os.path.join(la, "imput", "Helium", "Application", "chrome.exe"),
        os.path.join(la, "Helium", "Application", "chrome.exe"),
        os.path.join(pf, "Helium", "Application", "chrome.exe"),
        os.path.join(pfx86, "Helium", "Application", "chrome.exe"),
    ]
    # Registry: Installationspfad aus Deinstallations-Eintraegen
    if sys.platform == "win32":
        try:
            import winreg
            for hive, sub in (
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Helium"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Helium"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Helium"),
            ):
                try:
                    with winreg.OpenKey(hive, sub) as k:
                        for val in ("InstallLocation", "DisplayIcon", "UninstallString"):
                            try:
                                v, _ = winreg.QueryValueEx(k, val)
                            except OSError:
                                continue
                            v = str(v).strip().strip('"')
                            if v.lower().endswith(".exe"):
                                cands.append(v)
                            elif v:
                                cands.append(os.path.join(v, "Application", "chrome.exe"))
                                cands.append(os.path.join(v, "chrome.exe"))
                except OSError:
                    continue
        except Exception:
            pass
    # Duplikate entfernen, Reihenfolge behalten
    seen, out = set(), []
    for c in cands:
        n = os.path.normpath(c)
        if n not in seen:
            seen.add(n)
            out.append(c)
    return out


def helium_roots() -> list[str]:
    roots = []
    custom = env("HELIUM_ROOT")
    if custom:
        roots.append(custom)
    la = localappdata()
    roots.append(os.path.join(la, "Helium", "User Data"))
    roots.append(os.path.join(la, "imput", "Helium", "User Data"))
    roots.append(os.path.join(la, "imput", "Helium", "Application", "..", "User Data"))
    for exe in helium_exe_candidates():
        d = os.path.dirname(exe)
        roots.append(os.path.join(d, "..", "User Data"))
        roots.append(os.path.join(d, "User Data"))
    seen, out = set(), []
    for r in roots:
        n = os.path.normpath(r)
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def first_existing(roots) -> str | None:
    for r in roots:
        if os.path.isdir(r):
            return r
    return None


def find_helium_exe() -> str | None:
    for c in helium_exe_candidates():
        if os.path.isfile(c):
            return c
    return None


def helium_pids() -> list[int]:
    """Helium-Prozesse ueber den Ausfuehrungspfad erkennen (Chrome bleibt leben).

    Helium heisst intern ebenfalls chrome.exe - deshalb darf NICHT nach dem
    Bildnamen gesucht werden, sondern nach dem Pfad (Helium/imput).
    """
    if sys.platform != "win32":
        return []
    ps = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
              "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
              "Where-Object { $_.ExecutablePath -like '*Helium*' -or "
              "$_.ExecutablePath -like '*imput*' } | "
              "Select-Object -ExpandProperty ProcessId"],
             timeout=20)
    pids = []
    if ps is not None and ps.returncode == 0:
        for line in ps.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
    return pids


def quit_helium() -> bool:
    if flag("SKIP_QUIT"):
        return False
    pids = helium_pids()
    if not pids:
        return False
    log("  Helium wird geschlossen (PIDs: %s) ..." % ", ".join(map(str, pids[:12])))
    for pid in pids:
        r = run(["taskkill", "/PID", str(pid), "/T", "/F"], timeout=15)
        if r is not None and r.returncode != 0:
            try:
                os.kill(pid, 9)  # type: ignore[attr-defined]
            except Exception:
                pass
    deadline = time.time() + 15
    while time.time() < deadline:
        alive = [p for p in helium_pids() if p in pids]
        if not alive:
            break
        time.sleep(0.3)
    return True


def relaunch_helium() -> None:
    if flag("SKIP_RELAUNCH"):
        return
    exe = find_helium_exe()
    if exe and os.path.isfile(exe):
        try:
            subprocess.Popen([exe], close_fds=True)
            ok("Helium wird neu gestartet.")
            return
        except OSError:
            pass
    warn("Helium konnte nicht automatisch neu gestartet werden (bitte selbst oeffnen).")


# ---------------------------------------------------------------------------
# SQLite-Helfer
# ---------------------------------------------------------------------------
def ro_uri(path: str) -> str:
    return "file:" + urllib.parse.quote(os.path.abspath(path), safe="/") + "?mode=ro"


def snapshot_db(path: str, dest: str) -> str:
    """Konsistente Kopie einer (ggf. offenen, WAL-) SQLite-DB."""
    src = sqlite3.connect(ro_uri(path), uri=True, timeout=10)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)  # spielt ein vorhandenes WAL automatisch ein
    finally:
        src.close()
        dst.close()
    return dest


def table_columns(con) -> list:
    return [r[1] for r in con.execute("PRAGMA table_info(cookies)").fetchall()]


def table_info(con) -> list:
    return con.execute("PRAGMA table_info(cookies)").fetchall()


def meta_version(con) -> int:
    try:
        row = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
        return int(row[0]) if row else 0
    except (sqlite3.Error, ValueError, TypeError):
        return 0


def count_cookies(con) -> int:
    try:
        return int(con.execute("SELECT COUNT(*) FROM cookies").fetchone()[0])
    except sqlite3.Error:
        return -1


def sample_rows(con, limit: int = 12) -> list:
    try:
        cols = table_columns(con)
        if "host_key" not in cols or "encrypted_value" not in cols:
            return []
        return con.execute(
            "SELECT host_key, encrypted_value FROM cookies "
            "WHERE encrypted_value IS NOT NULL AND length(encrypted_value) > 3 "
            "LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error:
        return []


def probe_key(con, raw_key: bytes):
    """-> (gueltig, Methode, hat_hash_prefix) oder (False, None, None)."""
    yes = no = 0
    method = None
    for host, blob in sample_rows(con):
        plain, m = chromium_decrypt_v10(bytes(blob), raw_key)
        if plain is None:
            continue
        method = m
        if len(plain) >= 32 and plain[:32] == host_hash(host or ""):
            yes += 1
        elif looks_printable(plain):
            no += 1
    if yes == 0 and no == 0:
        return (False, None, None)
    return (True, method, yes >= no)


def resolve_key(cached: bytes | None, validation_con, label: str, user_data_root: str):
    """Nimmt den gecachten Schluessel, wenn er gegen echte Cookies prueft."""
    if cached is not None and validation_con is not None:
        valid, _, _ = probe_key(validation_con, cached)
        if valid:
            ok("%s-Schluessel aus Cache (kein DPAPI-Aufruf noetig)." % label)
            return cached
    log("  %s-Schluessel wird aus der Local State (DPAPI) gelesen ..." % label)
    key, v20 = load_v10_key(user_data_root, label)
    if key is None:
        if v20:
            raise Fatal(
                "Fuer %s wurde nur ein v20/App-Bound-Schluessel gefunden.\n"
                "  v20 braucht SYSTEM-Zugriff und kann hier nicht entschluesselt werden.\n"
                "  Details: README.md, Abschnitt 'Chrome 127+ / v20'." % label)
        raise Fatal(
            "Kein %s-Schluessel in der Local State gefunden.\n"
            "  Bitte %s einmal starten und das Tool erneut ausfuehren." % (label, label))
    if validation_con is not None:
        valid, _, _ = probe_key(validation_con, key)
        if not valid:
            warn("Der %s-Schluessel passt nicht zu den Cookies - weiter ohne Pruefung." % label)
    ok("%s-Schluessel gefunden." % label)
    return key


# ---------------------------------------------------------------------------
# Pfad-Erkennung (Profile + Cookies-Datenbanken)
# ---------------------------------------------------------------------------
def find_cookie_dbs(root: str) -> dict:
    """Profilname -> Liste aller Cookies-DBs (inkl. Network/Cookies)."""
    out = {}
    if not root or not os.path.isdir(root):
        return out
    try:
        entries = sorted(os.listdir(root))
    except OSError as e:
        raise Fatal("Kann %s nicht lesen (%s)." % (root, e))
    for name in entries:
        p = os.path.join(root, name)
        if not os.path.isdir(p):
            continue
        found = []
        for rel in (os.path.join("Network", "Cookies"), "Cookies"):
            f = os.path.join(p, rel)
            if os.path.isfile(f) and os.path.getsize(f) >= 512:
                found.append(f)
        for f in glob.glob(os.path.join(p, "*", "Cookies")):
            f = os.path.normpath(f)
            if os.path.isfile(f) and f not in found:
                found.append(f)
        if found:
            out[name] = found
    return out


def target_paths_for(helium_root: str, profile: str, existing: list) -> list:
    if existing:
        return existing
    d = os.path.join(helium_root, profile)
    return [os.path.join(d, "Network", "Cookies"), os.path.join(d, "Cookies")]


# ---------------------------------------------------------------------------
# Transformation (entschluesseln -> neu verschluesseln)
# ---------------------------------------------------------------------------
def transform_payload(enc: bytes, plain_value, host_key: str,
                      src_key: bytes, dst_key: bytes,
                      src_method: str, dst_method: str,
                      src_hash: bool, dst_hash: bool) -> tuple:
    """-> (neuer encrypted_value, Wertlaenge, Fehler, ist_v20)."""
    if enc and len(enc) > 3:
        if enc[:3] == b"v20":
            return (None, 0, "v20/App-Bound (SYSTEM-Zugriff noetig)", True)
        if enc[:3] != b"v10":
            return (None, 0, "unbekanntes Format", False)
        plain, _m = chromium_decrypt_v10(enc, src_key)
        if plain is None:
            return (None, 0, "Entschluesselung fehlgeschlagen", False)
        if src_hash:
            if len(plain) >= 32 and plain[:32] == host_hash(host_key):
                value_bytes = plain[32:]
            else:
                return (None, 0, "Hash-Praefix fehlt (falscher Schluessel?)", False)
        else:
            value_bytes = plain
    else:
        # Aeltere / unverschluesselte Cookies: Klartext aus der value-Spalte
        if isinstance(plain_value, bytes):
            value_bytes = plain_value
        else:
            value_bytes = (plain_value or "").encode("utf-8")
    payload = (host_hash(host_key) if dst_hash else b"") + value_bytes
    return (chromium_encrypt_v10(payload, dst_key, dst_method), len(value_bytes), None, False)


# Kanonisches Chromium-v24-Schema (wie im Original).
CANON_COLS = [
    "creation_utc", "host_key", "top_frame_site_key", "name", "value",
    "encrypted_value", "path", "expires_utc", "is_secure", "is_httponly",
    "last_access_utc", "has_expires", "is_persistent", "priority",
    "samesite", "source_scheme", "source_port", "last_update_utc",
    "source_type", "has_cross_site_ancestor",
]
CANON_TYPES = {
    "creation_utc": "INTEGER", "host_key": "TEXT", "top_frame_site_key": "TEXT",
    "name": "TEXT", "value": "TEXT", "encrypted_value": "BLOB", "path": "TEXT",
    "expires_utc": "INTEGER", "is_secure": "INTEGER", "is_httponly": "INTEGER",
    "last_access_utc": "INTEGER", "has_expires": "INTEGER",
    "is_persistent": "INTEGER", "priority": "INTEGER", "samesite": "INTEGER",
    "source_scheme": "INTEGER", "source_port": "INTEGER",
    "last_update_utc": "INTEGER", "source_type": "INTEGER",
    "has_cross_site_ancestor": "INTEGER",
}


def canonical_rows(con):
    cols = table_columns(con)
    present = [c for c in CANON_COLS if c in cols]
    sql = "SELECT " + ", ".join('"%s"' % c for c in present) + " FROM cookies"
    out = []
    for raw in con.execute(sql):
        d = {c: COLUMN_DEFAULTS.get(c, 0) for c in CANON_COLS}
        for c, v in zip(present, raw):
            if isinstance(v, memoryview):
                v = bytes(v)
            d[c] = v
        out.append(tuple(d[c] for c in CANON_COLS))
    return out


def make_combined_snapshot(dest: str, row_groups: list) -> str:
    if os.path.isfile(dest):
        os.remove(dest)
    con = sqlite3.connect(dest)
    ddl = ", ".join('"%s" %s NOT NULL' % (c, CANON_TYPES[c]) for c in CANON_COLS)
    con.execute("CREATE TABLE meta(key TEXT NOT NULL UNIQUE PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO meta VALUES('version','24')")
    con.execute("INSERT INTO meta VALUES('last_compatible_version','24')")
    con.execute("CREATE TABLE cookies(%s)" % ddl)
    con.execute("CREATE UNIQUE INDEX cookies_unique_index ON cookies("
                "host_key, top_frame_site_key, has_cross_site_ancestor, "
                "name, path, source_scheme, source_port)")
    sql = "INSERT OR REPLACE INTO cookies(%s) VALUES(%s)" % (
        ", ".join(CANON_COLS), ", ".join("?" * len(CANON_COLS)))
    for rows in row_groups:
        for r in rows:
            try:
                con.execute(sql, r)
            except sqlite3.Error:
                pass
    con.commit()
    con.close()
    return dest


def merge_into_target(target_db: str, src_rows: list, src_cols: list,
                      src_key: bytes, dst_key: bytes,
                      src_method: str, dst_method: str,
                      src_hash: bool) -> dict:
    stats = {"inserted": 0, "failed": 0, "skipped_v20": 0, "before": 0, "after": 0, "errors": []}
    con = sqlite3.connect(target_db, timeout=20, isolation_level=None)
    try:
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("PRAGMA journal_mode=DELETE")
        except sqlite3.Error:
            pass
        stats["before"] = count_cookies(con)
        dst_hash = meta_version(con) >= 24
        info = table_info(con)
        tcols = [r[1] for r in info]
        common = [c for c in tcols if c in src_cols]
        if "encrypted_value" not in common and "encrypted_value" in tcols:
            common.append("encrypted_value")
        extra = []
        for cid, name, typ, notnull, dflt, pk in info:
            if name in common or pk:
                continue
            if notnull and dflt is None:
                extra.append(name)
        allcols = common + extra
        placeholders = ", ".join("?" for _ in allcols)
        sql = "INSERT OR REPLACE INTO cookies (%s) VALUES (%s)" % (
            ", ".join('"%s"' % c.replace('"', '""') for c in allcols), placeholders)

        con.execute("BEGIN")
        for row in src_rows:
            d = dict(zip(src_cols, row))
            host = d.get("host_key", "")
            if isinstance(host, bytes):
                host = host.decode("utf-8", "replace")
            enc = d.get("encrypted_value", b"")
            enc = bytes(enc) if isinstance(enc, (bytes, bytearray, memoryview)) else b""
            new_enc, _, err, is_v20 = transform_payload(
                enc, d.get("value", ""), host, src_key, dst_key,
                src_method, dst_method, src_hash, dst_hash)
            if err:
                if is_v20:
                    stats["skipped_v20"] += 1
                else:
                    stats["failed"] += 1
                    if len(stats["errors"]) < 8:
                        stats["errors"].append("%s/%s: %s" % (host, d.get("name", "?"), err))
                continue
            values = []
            for c in allcols:
                if c == "encrypted_value":
                    values.append(new_enc)
                elif c == "value":
                    values.append("")  # niemals beide gleichzeitig befuellen!
                elif c == "is_persistent" and FORCE_PERSISTENT:
                    values.append(1)
                elif c in d:
                    v = d[c]
                    values.append(bytes(v) if isinstance(v, memoryview) else v)
                else:
                    values.append(COLUMN_DEFAULTS.get(c, 0))
            try:
                con.execute(sql, values)
                stats["inserted"] += 1
            except sqlite3.Error as e:
                stats["failed"] += 1
                if len(stats["errors"]) < 8:
                    stats["errors"].append("%s/%s: %s" % (host, d.get("name", "?"), e))
        con.commit()
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        stats["after"] = count_cookies(con)
    finally:
        con.close()
    for suffix in ("-wal", "-shm"):
        try:
            p = target_db + suffix
            if os.path.isfile(p) and os.path.getsize(p) <= 64 * 1024:
                os.remove(p)
        except OSError:
            pass
    return stats


def build_clone(source_db: str, src_key: bytes, dst_key: bytes,
                src_method: str, dst_method: str,
                src_hash: bool, dst_hash: bool, dest: str) -> dict:
    stats = {"inserted": 0, "failed": 0, "skipped_v20": 0, "before": 0, "after": 0, "errors": []}
    shutil.copy2(source_db, dest)
    con = sqlite3.connect(dest, timeout=20, isolation_level=None)
    try:
        try:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("UPDATE OR IGNORE meta SET value='24' WHERE key='version'")
            con.execute("UPDATE OR IGNORE meta SET value='24' "
                        "WHERE key='last_compatible_version'")
        except sqlite3.Error:
            pass
        stats["before"] = count_cookies(con)
        cur = con.execute("SELECT rowid, host_key, value, encrypted_value FROM cookies")
        updates = []
        dead = []
        for rowid, host, value, enc in cur.fetchall():
            if isinstance(host, bytes):
                host = host.decode("utf-8", "replace")
            enc = bytes(enc) if isinstance(enc, (bytes, bytearray, memoryview)) else b""
            new_enc, _, err, is_v20 = transform_payload(
                enc, value, host, src_key, dst_key,
                src_method, dst_method, src_hash, dst_hash)
            if err:
                # Nicht uebertragbare Zeilen (v20 / defekt) sauber entfernen,
                # statt tote, unlesbare Zeilen im Klon zu hinterlassen.
                dead.append((rowid,))
                if is_v20:
                    stats["skipped_v20"] += 1
                else:
                    stats["failed"] += 1
                    if len(stats["errors"]) < 8:
                        stats["errors"].append("%s: %s" % (host, err))
                continue
            updates.append((new_enc, 1 if FORCE_PERSISTENT else 0, rowid))
        con.execute("BEGIN")
        con.executemany(
            "UPDATE cookies SET encrypted_value=?, value='', "
            "is_persistent=CASE WHEN ?=1 THEN 1 ELSE is_persistent END WHERE rowid=?",
            updates)
        con.executemany("DELETE FROM cookies WHERE rowid=?", dead)
        con.commit()
        stats["after"] = count_cookies(con)
        stats["inserted"] = len(updates)
    finally:
        con.close()
    return stats


# ---------------------------------------------------------------------------
# Hauptprogramm
# ---------------------------------------------------------------------------
def write_logfile() -> None:
    try:
        os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
        with open(LOGFILE, "w", encoding="utf-8") as f:
            f.write("\n".join(_LOG) + "\n")
    except OSError:
        pass


def main() -> int:
    os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
    started = _dt.datetime.now()
    log("=" * 66)
    log("  CHROME  ->  HELIUM   |   Cookie-Migration v" + VERSION)
    log("  " + started.strftime("%d.%m.%Y  %H:%M:%S"))
    log("=" * 66)
    platform_check()

    chrome_root = env("CHROME_ROOT") or first_existing(chrome_roots())
    helium_root = env("HELIUM_ROOT") or first_existing(helium_roots())

    if not chrome_root:
        raise Fatal("Chrome-Profilordner nicht gefunden (%s\\Google\\Chrome\\User Data).\n"
                    "  Bitte Chrome einmal starten und das Tool erneut ausfuehren."
                    % localappdata())
    if not helium_root:
        helium_root = helium_roots()[0]
        os.makedirs(helium_root, exist_ok=True)
        ok("Helium-Profilordner erstellt: " + helium_root)
    log("  Chrome : " + chrome_root)
    log("  Helium : " + helium_root)
    log("  Krypto : %s" % _BACKEND)

    chrome_profiles = find_cookie_dbs(chrome_root)
    helium_profiles = find_cookie_dbs(helium_root)
    if not chrome_profiles:
        raise Fatal("Keine Chrome-Cookies-Datenbank gefunden. "
                    "Ist Chrome installiert und wurde es schon benutzt?")

    log("  Gefunden: %d Chrome-Profil(e), %d Helium-Profil(e)."
        % (len(chrome_profiles), len(helium_profiles)))

    # Backup (exakte 1:1-Kopien VOR jeder Aenderung)
    backup = os.path.join(SUPPORT, "Backups", started.strftime("%Y-%m-%d_%H-%M-%S"))
    os.makedirs(backup, exist_ok=True)
    backed_up = 0
    for label, profiles in (("Chrome", chrome_profiles), ("Helium-before", helium_profiles)):
        for prof, paths in profiles.items():
            for p in paths:
                try:
                    rel = os.path.relpath(p, userprofile())
                    d = os.path.join(backup, label, rel)
                    os.makedirs(os.path.dirname(d), exist_ok=True)
                    shutil.copy2(p, d)
                    for s in ("-wal", "-shm"):
                        if os.path.isfile(p + s):
                            shutil.copy2(p + s, d + s)
                    backed_up += 1
                except OSError as e:
                    warn("Konnte %s nicht sichern: %s" % (p, e))
    log("  Backup: %d Datei(en) in %s" % (backed_up, backup))

    # Helium muss geschlossen sein, sonst ueberschreibt es unsere Aenderungen.
    if quit_helium():
        ok("Helium wurde geschlossen.")
    else:
        log("  Helium lief nicht (oder Schliessen ist uebersprungen).")

    # --- Schluessel --------------------------------------------------------
    cache = cache_load()
    tmpdir = tempfile.mkdtemp(prefix="chrome2helium-")
    try:
        # Chrome-Snapshots (konsistent, auch wenn Chrome offen ist).
        usable = {}
        for prof, paths in chrome_profiles.items():
            groups, metas = [], []
            slug = re.sub(r"\W+", "_", prof)
            for i, p in enumerate(paths):
                snap = os.path.join(tmpdir, "chrome_%s_%d.db" % (slug, i))
                try:
                    snapshot_db(p, snap)
                except sqlite3.Error as e:
                    warn("Chrome-DB %s ist nicht lesbar: %s" % (p, e))
                    continue
                con = sqlite3.connect(snap)
                c = table_columns(con)
                if "host_key" not in c:
                    con.close()
                    continue
                metas.append(meta_version(con))
                groups.append(canonical_rows(con))
                con.close()
                try:
                    shutil.copy2(snap, os.path.join(
                        backup, "Chrome", os.path.relpath(p, userprofile()) + ".snapshot"))
                except OSError:
                    pass
            if not groups:
                continue
            combined = os.path.join(tmpdir, "src_%s.db" % slug)
            make_combined_snapshot(combined, groups)
            con = sqlite3.connect(combined)
            rows = con.execute("SELECT " + ", ".join(CANON_COLS) +
                               " FROM cookies").fetchall()
            con.close()
            if rows:
                usable[prof] = (combined, rows, max(metas) if metas else 0)
        if not usable:
            raise Fatal("Keine lesbaren Cookies in einer Chrome-Datenbank gefunden.")
        total_chrome = sum(len(v[1]) for v in usable.values())
        log("  Chrome-Cookies insgesamt: %d (aus %d Profil(en))."
            % (total_chrome, len(usable)))

        probe_con = sqlite3.connect(next(iter(usable.values()))[0])
        chrome_key = resolve_key(cache.get("chrome"), probe_con, "Chrome", chrome_root)

        src_method = "gcm"
        src_hash = None
        valid, detected_method, detected_hash = probe_key(probe_con, chrome_key)
        if valid:
            src_method = detected_method or "gcm"
            src_hash = detected_hash
        if src_hash is None:
            src_hash = max(v[2] for v in usable.values()) >= 24
        try:
            probe_con.close()
        except sqlite3.Error:
            pass
        log("  Chrome-Format: %s, %s" % (
            "AES-GCM" if src_method == "gcm" else "AES-CBC",
            "SHA-256-Domain-Praefix (Schema >= 24)" if src_hash else "altes Format"))

        def find_probe(profiles):
            for paths in profiles.values():
                for p in paths:
                    try:
                        con = sqlite3.connect(ro_uri(p), uri=True, timeout=5)
                        if sample_rows(con):
                            return con
                        con.close()
                    except sqlite3.Error:
                        pass
            return None

        hel_probe = find_probe(helium_profiles)
        helium_key = resolve_key(cache.get("helium"), hel_probe, "Helium", helium_root)
        dst_method = "gcm"
        if hel_probe is not None:
            valid_h, method_h, _ = probe_key(hel_probe, helium_key)
            if valid_h and method_h:
                dst_method = method_h
            try:
                hel_probe.close()
            except sqlite3.Error:
                pass
        log("  Helium-Format: %s" % ("AES-GCM" if dst_method == "gcm" else "AES-CBC"))

        cache["chrome"] = chrome_key
        cache["helium"] = helium_key
        cache_save(cache)

        # --- Migration -----------------------------------------------------
        grand = {"inserted": 0, "failed": 0, "skipped_v20": 0, "before": 0,
                 "after": 0, "errors": [], "targets": 0}
        for prof in sorted(usable):
            combined, rows, _meta = usable[prof]
            tgt_prof = prof if (prof in helium_profiles or prof == "Default") else "Default"
            existing = helium_profiles.get(tgt_prof, [])
            targets = target_paths_for(helium_root, tgt_prof, existing)
            log("  Profil '%s' -> Helium '%s' (%d Cookies, %d Ziel-DB(s))"
                % (prof, tgt_prof, len(rows), len(targets)))

            for t in targets:
                os.makedirs(os.path.dirname(t), exist_ok=True)
                is_new = not os.path.isfile(t)
                if is_new:
                    st = build_clone(combined, chrome_key, helium_key,
                                     src_method, dst_method, src_hash, True, t)
                else:
                    st = merge_into_target(t, rows, CANON_COLS, chrome_key, helium_key,
                                           src_method, dst_method, src_hash)
                grand["inserted"] += st["inserted"]
                grand["failed"] += st["failed"]
                grand["skipped_v20"] += st["skipped_v20"]
                grand["before"] += st["before"]
                grand["after"] += st["after"]
                grand["targets"] += 1
                grand["errors"].extend(st["errors"][:4])
                ok("%s : %d geschrieben (%d -> %d Cookies)%s" % (
                    os.path.relpath(t, helium_root), st["inserted"],
                    st["before"], st["after"], " [neu erstellt]" if is_new else ""))

        # --- Verifizierung -------------------------------------------------
        verified = 0
        for prof, paths in find_cookie_dbs(helium_root).items():
            for p in paths:
                try:
                    con = sqlite3.connect(ro_uri(p), uri=True, timeout=10)
                    want_hash = meta_version(con) >= 24
                    good, bad = 0, 0
                    for host, blob in sample_rows(con, 25):
                        plain, _m = chromium_decrypt_v10(bytes(blob), helium_key)
                        if plain is None:
                            bad += 1
                        elif want_hash:
                            if plain[:32] == host_hash(host or ""):
                                good += 1
                            else:
                                bad += 1
                        else:
                            good += 1
                    con.close()
                    verified += good
                    if bad:
                        warn("Verifizierung: %d Cookie(s) in %s konnten nicht gelesen werden."
                             % (bad, p))
                except sqlite3.Error:
                    pass
        ok("Verifizierung: %d Cookies erfolgreich mit dem Helium-Schluessel entschluesselt."
           % verified)

        # --- Bericht -------------------------------------------------------
        report = [
            "Chrome -> Helium Cookie-Migration",
            "Datum: " + started.strftime("%d.%m.%Y %H:%M:%S"),
            "",
            "Chrome-Profile       : %d" % len(usable),
            "Chrome-Cookies       : %d" % total_chrome,
            "Zeilen geschrieben   : %d" % grand["inserted"],
            "Fehlgeschlagen       : %d" % grand["failed"],
            "v20 uebersprungen    : %d" % grand["skipped_v20"],
            "Ziel-Datenbanken     : %d" % grand["targets"],
            "Cookies vorher       : %d" % grand["before"],
            "Cookies nachher      : %d" % grand["after"],
            "Verifiziert          : %d" % verified,
            "Session-Cookies behalten: %s" % ("ja" if FORCE_PERSISTENT else "nein"),
            "Backup               : " + backup,
            "",
        ]
        if grand["skipped_v20"]:
            report += [
                "Hinweis: %d Cookie(s) sind mit Chrome-App-Bound (v20) verschluesselt" % grand["skipped_v20"],
                "und wurden uebersprungen (SYSTEM-Zugriff noetig).",
                "Details: README.md, Abschnitt 'Chrome 127+ / v20'.",
                "",
            ]
        if grand["errors"]:
            report += ["Hinweise:"] + ["  - " + e for e in grand["errors"]] + [""]
        with open(os.path.join(backup, "REPORT.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(report))

        log("")
        log("  FERTIG: %d Cookie-Zeilen uebertragen, %d Fehler, %d v20 uebersprungen."
            % (grand["inserted"], grand["failed"], grand["skipped_v20"]))
        log("  Backup + Bericht: " + backup)
        if grand["failed"]:
            for e in grand["errors"][:6]:
                warn(e)
        if grand["skipped_v20"]:
            warn("%d v20-Cookie(s) uebersprungen - siehe README (Chrome 127+ / v20)." % grand["skipped_v20"])
        relaunch_helium()
        return 0 if grand["inserted"] > 0 else 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        write_logfile()


def restore() -> int:
    log("=" * 66)
    log("  CHROME -> HELIUM  |  Backup wiederherstellen")
    log("=" * 66)
    platform_check()
    sup = os.path.join(SUPPORT, "Backups")
    latest = ""
    if os.path.isdir(sup):
        for d in sorted(os.listdir(sup)):
            full = os.path.join(sup, d)
            if os.path.isdir(os.path.join(full, "Helium-before")):
                latest = full
    if not latest:
        log("")
        log("  Kein Backup gefunden unter:")
        log("  " + sup)
        log("")
        return 1
    log("  Verwende: " + latest)
    log("")
    if quit_helium():
        ok("Helium wurde geschlossen.")
    src = os.path.join(latest, "Helium-before")
    n = 0
    files = []
    for dirpath, _dirs, filenames in os.walk(src):
        for fn in filenames:
            files.append(os.path.join(dirpath, fn))
    # 1) Hauptdatenbanken; WAL/SHM am Ziel entfernen, sonst wuerde Helium
    #    den alten Stand aus dem WAL einspielen.
    for f in files:
        rel = os.path.relpath(f, src)
        if rel.endswith("-wal") or rel.endswith("-shm"):
            continue
        dest = os.path.join(userprofile(), rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        for s in ("-wal", "-shm"):
            try:
                os.remove(dest + s)
            except OSError:
                pass
        try:
            shutil.copy2(f, dest)
            n += 1
        except OSError as e:
            warn("Konnte %s nicht wiederherstellen: %s" % (dest, e))
    # 2) WAL/SHM aus dem Backup ergaenzen (falls vorhanden)
    for f in files:
        rel = os.path.relpath(f, src)
        if not (rel.endswith("-wal") or rel.endswith("-shm")):
            continue
        dest = os.path.join(userprofile(), rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            shutil.copy2(f, dest)
            n += 1
        except OSError:
            pass
    log("")
    if n > 0:
        log("  Fertig: %d Datei(en) wiederhergestellt." % n)
        log("  Helium kann jetzt wie gewohnt geoeffnet werden.")
        return 0
    log("  FEHLER: Das Backup enthielt keine wiederherstellbaren Dateien.")
    return 1


def print_help() -> int:
    print("Chrome -> Helium Cookie-Migration (Windows 10/11) v" + VERSION)
    print("")
    print("Aufruf:")
    print("  ChromeToHelium.bat          Migration ausfuehren (Doppelklick)")
    print("  Restore-Backup.bat          Letztes Backup wiederherstellen")
    print("  python engine.py            Migration ausfuehren")
    print("  python engine.py --restore  Letztes Backup wiederherstellen")
    print("  python engine.py --help     Diese Hilfe anzeigen")
    print("")
    print("Details: README.md")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    try:
        if "--help" in args or "-h" in args:
            sys.exit(print_help())
        elif "--restore" in args:
            rc = restore()
            write_logfile()
            sys.exit(rc)
        else:
            sys.exit(main())
    except Fatal as e:
        log("")
        log("  FEHLER: " + str(e))
        write_logfile()
        sys.exit(2)
    except Exception as e:  # unerwarteter Fehler: sauber melden
        import traceback
        log("")
        log("  UNERWARTETER FEHLER: %s: %s" % (type(e).__name__, e))
        _LOG.append(traceback.format_exc())
        write_logfile()
        sys.exit(3)
