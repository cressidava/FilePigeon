"""The update-signing key: password-protected, with the password kept
encrypted for your Windows account (DPAPI), so neither file alone is enough
and the password is never typed, printed or stored in plain text.

    python scripts/signing.py new           # make a new key (first time / rotation)
    python scripts/signing.py show-password # print the password, to back it up
                                            # (run in your own terminal only)

The key and password live in %USERPROFILE%\\.filepigeon-release\\ (never in
the repo). Back up updater-v2.key AND its password (show-password) together.
"""

import base64
import ctypes
import ctypes.wintypes as wt
import os
import pathlib
import secrets
import subprocess
import sys

HOME = pathlib.Path(os.environ.get("FILEPIGEON_RELEASE_DIR", pathlib.Path.home() / ".filepigeon-release"))
KEY = HOME / "updater-v2.key"
PASSWORD = HOME / "updater-v2.password.dpapi"
ENTROPY = b"FilePigeon update signing key v2"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _Blob:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    inp, extra, out = _blob(data), _blob(ENTROPY), _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(inp), None, ctypes.byref(extra), None, None, 0x1, ctypes.byref(out))  # UI_FORBIDDEN
    if not ok:
        raise OSError(f"Windows couldn't {'encrypt' if protect else 'decrypt'} the signing password")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def password() -> str:
    """The signing key's password (decrypted for this Windows account)."""
    return _dpapi(base64.b64decode(PASSWORD.read_text()), protect=False).decode()


def new_key():
    if KEY.exists():
        sys.exit(f"{KEY} already exists; move it away first if you really want a new one")
    HOME.mkdir(parents=True, exist_ok=True)
    pw = secrets.token_urlsafe(32)
    PASSWORD.write_text(base64.b64encode(_dpapi(pw.encode(), protect=True)).decode())
    r = subprocess.run(
        ["cargo", "tauri", "signer", "generate", "--ci", "-p", pw, "-w", str(KEY)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not KEY.exists():
        PASSWORD.unlink(missing_ok=True)
        sys.exit("key generation failed:\n" + r.stderr[-2000:])
    print(f"New signing key: {KEY}")
    print(f"Public key (goes in gui/tauri.conf.json): {KEY.with_suffix('.key.pub')}")


def sign(file: pathlib.Path, key: pathlib.Path = KEY, pw: str | None = None) -> pathlib.Path:
    """Sign an installer; returns the .sig path. The key and password reach only
    this one signing command, never the build."""
    env = dict(os.environ)
    env.pop("TAURI_SIGNING_PRIVATE_KEY", None)
    env["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"] = password() if pw is None else pw
    r = subprocess.run(["cargo", "tauri", "signer", "sign", "-f", str(key), str(file)], env=env, capture_output=True, text=True)
    sig = file.with_name(file.name + ".sig")
    if r.returncode != 0 or not sig.exists():
        sys.exit("signing failed:\n" + r.stderr[-2000:])
    return sig


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "new":
        new_key()
    elif cmd == "show-password":
        print(password())
    else:
        sys.exit(__doc__)
