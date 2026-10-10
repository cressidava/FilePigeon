"""Build and stage a FilePigeon release for automatic updates.

    python scripts/release.py 0.2.3 "What changed, in a sentence or two"

1. Sets the version (Cargo.toml [workspace.package]).
2. Builds the installer, then signs it in a separate step (scripts/signing.py:
   a password-protected key whose password is DPAPI-encrypted for your Windows
   account). The key never enters the build environment.
   --legacy-key signs with the old unprotected key instead (only needed once,
   for the release that moves installed copies onto the new key).
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import signing  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = os.environ.get("FILEPIGEON_SITE", "https://joinfp.panno.tech")
LEGACY_KEY = pathlib.Path.home() / ".filepigeon-release" / "updater.key"


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def as_tuple(v):
    return tuple(int(x) for x in v.split("."))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args or not re.fullmatch(r"\d+\.\d+\.\d+", args[0]):
        fail('usage: python scripts/release.py X.Y.Z "release notes" [--legacy-key] [--rebuild]')
    version, notes = args[0], (args[1] if len(args) > 1 else "")
    legacy = "--legacy-key" in sys.argv
    key = LEGACY_KEY if legacy else signing.KEY
    if not key.exists():
        fail(f"signing key not found at {key}")

    cargo = ROOT / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    m = re.search(r'(\[workspace\.package\][^\[]*?version = ")([^"]+)(")', text)
    if not m:
        fail("no [workspace.package] version in Cargo.toml")
    current = m.group(2)
    if as_tuple(version) < as_tuple(current) or (version == current and "--rebuild" not in sys.argv):
        fail(f"{version} isn't newer than {current} (add --rebuild to rebuild {current})")
    cargo.write_text(text[: m.start(2)] + version + text[m.end(2):], encoding="utf-8")
    print(f"version: {current} -> {version}")

    # Build without any signing key in the environment, so no dependency's
    # build script ever sees it; the update signature is made afterwards.
    env = {k: v for k, v in os.environ.items() if not k.startswith("TAURI_SIGNING_")}
    print("building the installer (a few minutes)...")
    build = subprocess.run(
        ["cargo", "tauri", "build", "--config", json.dumps({"bundle": {"createUpdaterArtifacts": False}})],
        cwd=ROOT / "gui", env=env, capture_output=True, text=True,
    )
    if build.returncode != 0:
        print(build.stdout[-3000:], build.stderr[-3000:], sep="\n")
        fail("build failed")

    bundle = ROOT / "target" / "release" / "bundle" / "nsis"
    exe = bundle / f"FilePigeon_{version}_x64-setup.exe"
    if not exe.exists():
        fail(f"expected {exe.name} in {bundle}")
    exe.with_name(exe.name + ".sig").unlink(missing_ok=True)
    print(f"signing with {'the legacy key' if legacy else 'the protected key'}...")
    sig = signing.sign(exe, key=key, pw="" if legacy else None)

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
