"""Build and stage a FilePigeon release for automatic updates.

    python scripts/release.py 0.2.1 "What changed, in a sentence or two"

1. Sets the version (Cargo.toml [workspace.package]).
2. Builds the signed installer. The signing key never leaves this PC: it's
   read from %USERPROFILE%\\.filepigeon-release\\updater.key (override with
   FILEPIGEON_UPDATER_KEY).
3. Puts the installer, and update/latest.json describing it, in web/.

Then upload the web folder to Cloudflare (Workers & Pages -> filepigeon ->
New deployment). Installed copies pick the update up within a few hours.
"""

import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = os.environ.get("FILEPIGEON_SITE", "https://joinfp.panno.tech")
KEY = pathlib.Path(os.environ.get("FILEPIGEON_UPDATER_KEY", pathlib.Path.home() / ".filepigeon-release" / "updater.key"))


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def as_tuple(v):
    return tuple(int(x) for x in v.split("."))


def main():
    if len(sys.argv) < 2 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[1]):
        fail('usage: python scripts/release.py X.Y.Z "release notes"')
    version, notes = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")

    cargo = ROOT / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    m = re.search(r'(\[workspace\.package\][^\[]*?version = ")([^"]+)(")', text)
    if not m:
        fail("no [workspace.package] version in Cargo.toml")
    current = m.group(2)
    if as_tuple(version) < as_tuple(current) or (version == current and "--rebuild" not in sys.argv):
        fail(f"{version} isn't newer than {current} (add --rebuild to rebuild {current})")
    if not KEY.exists():
        fail(f"signing key not found at {KEY}")
    cargo.write_text(text[: m.start(2)] + version + text[m.end(2):], encoding="utf-8")
    print(f"version: {current} -> {version}")

    env = dict(os.environ)
    env["TAURI_SIGNING_PRIVATE_KEY"] = KEY.read_text(encoding="utf-8").strip()
    env["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"] = ""
    print("building the signed installer (a few minutes)...")
    build = subprocess.run(["cargo", "tauri", "build"], cwd=ROOT / "gui", env=env, capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stdout[-3000:], build.stderr[-3000:], sep="\n")
        fail("build failed")

    bundle = ROOT / "target" / "release" / "bundle" / "nsis"
    exe = bundle / f"FilePigeon_{version}_x64-setup.exe"
    sig = bundle / f"FilePigeon_{version}_x64-setup.exe.sig"
    if not exe.exists() or not sig.exists():
        fail(f"expected {exe.name} and its .sig in {bundle}")

    web = ROOT / "web"
    update = web / "update"
    if update.exists():
        shutil.rmtree(update)
    update.mkdir()
    shutil.copy2(exe, update / exe.name)
    shutil.copy2(exe, web / "FilePigeon-setup.exe")
    manifest = {
        "version": version,
        "notes": notes,
        "pub_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": {
            "windows-x86_64": {
                "signature": sig.read_text(encoding="utf-8").strip(),
                "url": f"{SITE}/update/{exe.name}",
            }
        },
    }
    (update / "latest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"""
Ready: FilePigeon {version}
  web/FilePigeon-setup.exe          (download for new friends)
  web/update/{exe.name}
  web/update/latest.json            (what installed copies check)

Next: Cloudflare -> Workers & Pages -> filepigeon -> New deployment, upload the web folder.
Then commit: git commit -am "Release {version}" && git tag v{version} && git push --follow-tags""")


if __name__ == "__main__":
    main()
