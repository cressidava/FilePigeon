# FilePigeon

Secure, direct PC-to-PC file transfer on your local network or over the internet.

- **Pair once** with a one-time code like `95-lilac-alley-turtle`.
- **Accept or deny** every incoming transfer and every file request.
- **Shared folders** that paired PCs can browse and request files from (read-only).
- **Any file size**, streamed in chunks, with **resume** after interruptions and a BLAKE3 **integrity check** on every file.
- **Direct and end-to-end encrypted.** File data goes straight between the two PCs over QUIC/TLS 1.3.
- **No server needed on a shared network.** Paired PCs find each other privately on the local network. A rendezvous server is only needed to reach devices over the internet.
- **Invisible mode**, and per-device "appear offline".
- **No standing open ports.** Uses NAT hole punching. UPnP is a fallback that maps a port only while a session is active, then removes it.

## How it fits together

```
   PC A                     rendezvous server                    PC B
 filepigeon  ──QUIC──►   pigeon-rendezvous   ◄──QUIC──  filepigeon serve
      │        (introductions + pairing relay only)               ▲
      └──────────── direct QUIC, mutually authenticated ──────────┘
                     (all file data goes here)
```

**On the same network** there's no server at all. A PC looking for a paired device
sends a private local-network lookup, gets the device's address back, and connects directly.

**Over the internet**, two PCs behind home routers can't find each other on their own.
The optional rendezvous server tells each one the other's address and coordinates
the hole punch. It never sees file data, file names, or pairing codes.

Every connection tries these in order:

1. **Remembered address** and **local-network lookup**, in parallel and with no server. FilePigeon keeps its listening port stable across restarts, so the address a device was last reached at often still works.
2. **Direct connection** arranged by the rendezvous server (hole punching).
3. **Encrypted relay** through the rendezvous server, when a direct path is impossible (e.g. strict NAT on both ends). The two PCs still run their own key-pinned QUIC/TLS connection end to end, so the server only forwards ciphertext it can't read or alter undetected.

**No server at all (experimental, off by default):** with `filepigeon init --dht true` (or Settings → Network), devices find each other over the public BitTorrent DHT when no rendezvous server is set or reachable:

- Each PC keeps an encrypted "you can reach me at" note in the DHT for each paired device.
- To connect, a PC reads the note and leaves an encrypted "knock".
- The other PC checks for knocks every ~20 s and punches back through its router.

Every note's location, signing key and encryption key come from a secret only the two paired devices can compute (X25519 on their existing keys, so no re-pairing), and change every day. DHT nodes see random, unlinkable encrypted blobs.

Limits:

- Connecting this way can take up to a minute.
- It only works when both routers keep port numbers for outgoing traffic, which many home routers do and some don't.
- Like any DHT use, the DHT nodes you talk to see your IP address.

The Activity log (or terminal) says which route each connection used.

## Security model

| Concern | How FilePigeon handles it |
|---|---|
| Who can connect to me? | Two layers. First, each device's listening port sits behind a **stealth gate**: it ignores every packet unless the sender first knocks with a key derived from the secret only that pair of devices shares (X25519 on their pinned keys), bound to the receiving device. Strangers, unpaired devices and devices you've hidden from get no reply of any kind, not even a TLS handshake, so they can't learn the device is there or what its key is. Second, the connection itself is QUIC/TLS 1.3 with both sides pinned to each other's exact Ed25519 key. |
| Revoking a device | Unpairing, hiding, or turning off browse/auto-accept applies **immediately, including to connections already open**. Permissions are re-read for every request, and within about a second the service closes the device's connections and forgets the addresses its knocks admitted. |
| Pairing | SPAKE2 password-authenticated key exchange over the code. The relay cannot learn the key; a wrong guess fails and nothing is saved. Local-network pairing uses a throwaway certificate, so your real identity key is never shown to whoever answers. New pairings **can't browse your shares** until you allow it. |
| Can a stranger find my IP? | The server asks your PC before revealing your address, and your PC only approves paired, non-hidden devices. "Offline", "refused" and "relay full" all get the same answer at the same fixed delay. |
| Approvals | Every transfer and share request needs your OK unless you turned on auto-accept for that device (the desktop app confirms that with a native dialog). Silence means no; prompts auto-deny after 120 s. A device can have at most 2 requests waiting (16 in total), and only one approval pop-up is on screen at a time. Its Accept button arms only after it has been visible and focused for a second. |
| Size and resource abuse | Offers are checked for impossible sizes (no integer overflow, 1 PiB cap) and the largest file is always shown. Request messages are capped and must arrive within 30 s; memory grows only as data arrives; each device is limited to 8 connections and 8 streams on each. A second copy of a transfer that is already arriving is declined with a clear message. |
| Malicious file names | Paths are checked for `..`, absolute paths, drive letters, separators and slash look-alikes, control and invisible/bidi characters (so `invoice\u202Efdp.exe` can't pose as a PDF), and every Windows device name (`CON`, `NUL`, `COM¹`, `CONIN$`, ...). Received files never overwrite anything (names are reserved atomically), get the Windows "downloaded from the internet" mark, and peers can't write into the partial-files folder. |
| Peer-supplied text | Names, messages and listings from other devices are cleaned before they're stored or shown: invisible and direction-changing characters are removed or neutralised, terminal escape sequences can't run, and lengths are capped. Approval prompts show the device id next to the name. |
| Share escapes | Every requested path is canonicalized and must stay inside the share root; symlinks and junctions are not followed, and each file is re-checked right before it's read. Fetch replies must match what was requested. |
| Tampering or corruption | Every file is BLAKE3-verified end to end. A file that fails is discarded. |
| Local-network privacy | Nobody broadcasts "I'm here". A lookup carries a fresh nonce, a timestamp and a MAC under the pair's shared secret, bound to the device being looked for, so to anyone else it's random bytes, never linkable between lookups and impossible to forge from a public key. The answer is MACed too, so nobody on the network can redirect it. |
| Invisible / hidden | Invisible opens no ports at all and answers nothing; you can still send and browse. A device you hide from gets exactly what an offline device gives, on every path: silence from your gate, the same server answer at the same time, no local-network reply. |
| Open ports | Hole punching opens a temporary, outbound-initiated path. UPnP mappings get a 120 s lease, are renewed only during real sessions (not by repeated connection requests), and are deleted 30 s after going idle. |
| DHT discovery | Off by default. Records are encrypted to one specific paired device and re-keyed daily, so they can't be read, forged, or linked. Hidden devices get no record or knock response, and a missing record, a refusal and silence all take the same time. |
| Relay | Used only as a last resort, and only after the target PC approves. Ports are reserved per session from a pre-bound pool (silent when idle), released at once on refusal, bound to the first address that presents each random token, capped at 2 sessions per device and 4 per IP, 50 GiB and 12 hours per session. The two PCs' own encrypted, key-pinned connection runs through it. |
| Friends on your server | Each friend gets **their own key**, **locked to their PC**: the server refuses it from any other device, so a copied key is useless (keys not made for a known device lock to the first one that uses it). One friend can be cut off without re-keying anyone else; revoking closes their connections within seconds. Only admin devices you list on the server can create or revoke invites, and only while using the owner key, so a friend's key never grants that. A key given while pairing travels inside the pairing's encrypted channel and is only used by a PC that has no server yet (or for the same server); it never replaces a different one. |
| Server key on your PC | Never shown: the app only says it's saved. On Windows it's stored encrypted for your account (DPAPI), so the config file holds no readable key. |
| Rendezvous server | Clients pin the server's public key. **Stealth mode**: the server ignores every packet unless the sender's exact address (IP and port) has just sent a valid, fresh, single-use knock under a random secret that is never sent over the network; unauthenticated packets never reach the QUIC/TLS code. Small flow-control windows, connection caps per IP, and request/pairing-join limits per device and per IP across connections. It never logs the key. Shipped sandboxed with a minimal-privilege systemd unit. |

## Install (Windows)

Run `FilePigeon_0.1.0_x64-setup.exe`. It installs for your user only, with **no admin rights needed**, and includes:

- **FilePigeon** (`filepigeon-desktop.exe`): the desktop app, with Start menu and desktop shortcuts.
- **`filepigeon.exe`**: the command-line tool, in the same folder (`%LOCALAPPDATA%\FilePigeon`).

On first launch, name your PC (and optionally add a rendezvous server). **Start FilePigeon when I sign in** is checked by default on that screen; you can change it any time in Settings. It starts quietly in the tray.

The first time FilePigeon listens for connections, Windows Firewall asks whether to allow it. **Allow it on private networks only.**

Uninstalling removes the app and its start-at-login entry. Your settings, pairings and identity key (`%APPDATA%\FilePigeon`) are kept so a reinstall picks up where you left off; delete that folder to remove them too.

The installer is not code-signed yet, so Windows SmartScreen may warn the first time ("More info" → "Run anyway").

### Building the installer

```bash
cargo install tauri-cli --version "^2" --locked
cd gui
cargo tauri build
```

The installer lands in `target/release/bundle/nsis/`.

## Quick start (command line)

### 1. (Optional) Run a rendezvous server for internet use

Skip this if all your PCs share a network. Any always-on Linux machine you already have works; it needs almost no CPU, memory or bandwidth (unless it relays).

**Stealth mode (on by default).** The server ignores every packet unless the sender's exact address first sent a valid secret *knock* (a 40-byte packet your devices send automatically). It never replies to anyone else, so to scanners the port looks the same as one a firewall blocks. Because the check happens before the network code sees anything, strangers can't even reach the encrypted-connection code. An admitted address is forgotten after 60 s of silence and must knock again at least every 5 minutes (devices do this automatically every 20 s while connected). Idle relay ports stay bound and silent too.

**Setup on Linux (systemd):**

```bash
cargo build --release --bin pigeon-rendezvous
sudo install -m 755 target/release/pigeon-rendezvous /usr/local/bin/
sudo cp deploy/pigeon-rendezvous.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pigeon-rendezvous
# The server key your devices need (never written to the log):
sudo pigeon-rendezvous --show-key --key /var/lib/private/pigeon-rendezvous/rendezvous-key.pem
```

The service file is heavily sandboxed. The server runs as a throwaway user with no privileges, can't read your home directories or other services' data, sees a read-only system, and is capped at 256 MB of memory and half a CPU.

**The server key is a secret.** It's 128 hex characters: the server's identity key followed by a knock secret. `--show-key` prints the **owner key**, for your own devices. Give friends their own key instead (see below). Keys live in `/var/lib/pigeon-rendezvous/` (`rendezvous-key.pem`, `rendezvous-key.knock`, and `rendezvous-key.access` for friends' keys and admins); back them all up.

**Adding friends** is done in the app; nobody handles a key:

1. **You:** Devices → **Add a friend** → type their name → **Copy message**, and send it any way you like. It holds a link and a short code, e.g. `pigeon.example.com · tiger-maple-lotus-river-cedar`.
2. **Your friend:** clicks the link (it offers the download, then opens FilePigeon with the invite filled in), or opens FilePigeon → **I have an invite** and pastes or types it. A brand-new install needs only a name for the PC.
3. **Both screens show three check words.** Compare them (a call, a message), then click **Pair** in your pop-up. Their PC gets its own key to your server, locked to that PC.

An invite works **once, within 24 hours**, while your FilePigeon is running. Every secret is derived from the five words with Argon2 (slow on purpose, so the words can't be guessed even from overheard traffic); the key they unlock on your server is temporary and replaced by the friend's own device-locked key once paired. The check words come from the pairing's encryption, so a copied or intercepted invite shows different words, and nothing happens without your approval. For your own PCs side by side, **Pair a PC next to you** uses a short code and needs no server. (CLI: `filepigeon invite link "Sam"`; `filepigeon pair "<link or code>"`.)

**The invite page** (optional, recommended) makes the link clickable from any chat app: a static page in `web/` that reads the invite from the part of the link after `#`, which browsers never send to the server. Host it on Cloudflare Pages (free; see below) and set **Settings → Invite page** to its `/join` address. Without it, invites carry a `filepigeon://` link, which works once FilePigeon is installed but isn't clickable everywhere.

For all this, your PC must be an admin of the server, once:

```bash
filepigeon whoami                                    # on your PC: shows its public key
sudo pigeon-rendezvous --key /var/lib/private/pigeon-rendezvous/rendezvous-key.pem --add-admin <PUBLIC_KEY>
```

If your PC reaches the server by a LAN address, also set the address friends should use (Settings → **Address for friends**, or `filepigeon init --friend-address pigeon.example.com:7400`).

Managing keys (Settings → **Friends' keys** in the app, or):

```bash
filepigeon invite list                          # who has a key, and who's connected
filepigeon invite revoke "Sam (1c744f9a)"       # cut one off within seconds (or on the server: --revoke NAME)
filepigeon invite pending                       # invite links not used yet; `invite cancel "Sam"` cancels one
filepigeon invite create "Sam"                  # a raw key to hand over yourself (rarely needed)
```

**Router (only if the server is at home):** forward **UDP 7400** (and **UDP 7401–7404**, if you use the relay) to the server. For the strongest isolation, put the server on its own VLAN or DMZ, and/or uncomment `IPAddressDeny` in the service file. A service restart leaves the port unbound for a few seconds, and the kernel answers probes with "port unreachable" during that gap; a host firewall rule that drops (not rejects) those ports closes it.

| Option | Default | Meaning |
|---|---|---|
| `--show-key` | | Print the owner key (for your own devices) and exit. |
| `--invite NAME` / `--invites` / `--revoke NAME` | | Make a friend's key (printed), list them, or revoke one, then exit. |
| `--add-admin KEY` / `--admins` / `--remove-admin KEY` | | Manage which devices may make and revoke invites remotely, then exit. |
| `--relay-ports` | `7401-7432` (service file: `7401-7404`) | One port per relay session; the range size is the session limit. |
| `--relay-limit-mb` | `51200` (50 GiB) | Stop a relay session after this much data (`0` = no limit). |
| `--no-relay` | off | Only help with direct connections; never forward data. Only UDP 7400 needed. |
| `--no-stealth` | off | Answer anyone without a knock (not recommended). |

### Releasing updates

The desktop app updates itself: it checks `https://<invite site>/update/latest.json` a minute after starting and every 6 hours, downloads newer versions in the background, verifies their signature against the release key built into the app, and installs them when idle (no transfers, requests, pairing or do not disturb), then restarts. Settings → About & updates shows the version and has **Check for updates**; turning off **Install updates automatically** shows a **Restart to update** button instead.

To release:

```bash
python scripts/release.py 0.2.2 "What changed"
```

It sets the version (one `[workspace.package]` version for everything), builds the signed installer, and stages `web/FilePigeon-setup.exe`, `web/update/` and `web/update/latest.json`. Then upload the `web` folder as a new Cloudflare deployment.

The signing key lives outside the repo at `%USERPROFILE%\.filepigeon-release\updater.key` (its public half is in `gui/tauri.conf.json`). Back it up somewhere safe. If it's lost, installed copies can't accept new updates and everyone reinstalls once; if it leaks, someone could sign updates (they'd also need your invite site to deliver them).

### Invite page on Cloudflare Pages

1. Copy the installer into `web/` as `FilePigeon-setup.exe` (it's git-ignored).
2. Cloudflare dashboard → **Workers & Pages** → **Create** → **Pages** → **Upload assets** (direct upload), name the project, and upload the whole `web` folder.
3. In the project → **Custom domains**, add e.g. `fp.example.com` (Cloudflare creates the DNS record).
4. In FilePigeon → Settings → **Invite page**: `https://fp.example.com/join`.

To ship a new installer, upload the folder again as a new deployment. The page has a strict content security policy and sends no referrer (`web/_headers`).

### 2. On each PC

```bash
filepigeon init --name "Ava-Desktop"                                                   # local network only
filepigeon init --name "Ava-Desktop" --rendezvous your.server:7400 --rendezvous-key <KEY>  # plus internet (KEY from --show-key)
```

### 3. Pair (once)

```bash
filepigeon pair                         # PC A: shows a code
filepigeon pair 95-lilac-alley-turtle   # PC B: enters it
filepigeon pair --give-server           # (either side) also give a friend their own key to your server
```

Pairing works directly on the local network, or through the server when one is set up.

### 4. Use it

```bash
filepigeon serve                        # keep running to receive; prompts appear here
filepigeon send Ava-Laptop video.mkv photos/
filepigeon share add music D:\Music     # read-only share
filepigeon browse Ava-Desktop           # list their shares
filepigeon browse Ava-Desktop music/Jazz
filepigeon get Ava-Desktop music/Jazz/album --to D:\Incoming
```

### Desktop app

`filepigeon-desktop` gives you the same features with a window and a tray icon:

- Closing the window keeps FilePigeon running in the system tray. The tray menu has Open, Downloads folder, Invisible, Do not disturb, and Quit. Start it with `--hidden` to go straight to the tray.
- Every incoming transfer or file request opens a small **accept/deny pop-up** that stays on top. **Deny** is focused by default, Escape or closing the pop-up denies, and unanswered requests auto-deny.
- **Do not disturb** (sidebar, tray, or Settings):
  - **Off:** pop-ups appear immediately.
  - **Automatic** (the default): quiet while Windows reports a full-screen app, game, or presentation.
  - **On:** never pop up.

  While quiet, requests are queued on the **Requests** page and wait up to 14 minutes instead of being denied. When quiet ends, anything still waiting pops up.
- Drag files onto the window to send them to a paired device.

The desktop app and `filepigeon serve` share the same identity and settings. Only one of them can run at a time.

### Managing peers

```bash
filepigeon peers
filepigeon trust Ava-Laptop --browse true         # let them browse and request your shares (off by default)
filepigeon trust Ava-Laptop --auto-accept true    # skip prompts (your own PCs only)
filepigeon unpair Ava-Laptop
filepigeon trust Ava-Laptop --hidden true         # appear offline to them
filepigeon visibility invisible                   # nobody can find you; restart serve to apply
filepigeon visibility online
```

Settings live in `%APPDATA%\FilePigeon\config` (override with `FILEPIGEON_HOME`).

## Known risks (accepted)

These are understood and left as they are, because fixing them would cost more than they're worth or isn't possible:

- **Knock replay by someone on the network path.** A knock can't be tied to the sender's address, since routers rewrite addresses. Someone who can see and block your traffic (your ISP, or someone on the same Wi-Fi) could drop your knock and use it from their own address within a couple of seconds. That only gets them past the stealth gate: they'd still face TLS pinned to keys they don't have, so they learn that something is listening, nothing more. On the rendezvous server it can't grant admin rights either, since those also need the admin device's own key.
- **An invite is a secret until it's used.** Whoever pastes it first gets the pairing request, so send it to the right person. Your approval pop-up names the PC that used it, and nothing happens unless you accept.
- **A server offered while pairing is used automatically** when this PC has none. The person you paired with then runs the server your PC uses, so it learns your PC's IP address and when it's online, never your files or who else you talk to. It never replaces a server you already use.
- **Knocks go to every candidate address.** When connecting, a device knocks on each address the server or address book suggests, including stale ones. A knock reveals nothing and can't be reused for a different device, but whoever now holds an old address sees a few 40-byte packets.
- **Local-network pairing can be disrupted.** Anyone on the same network can answer a pairing lookup first. They can't learn or guess the code (SPAKE2 allows one guess, and a failed code is refused afterwards), but they can make that attempt fail. Use a new code, or pair through the server.
- **Pairing codes are short on purpose.** A code allows exactly one guess, and the server forgets it after a few minutes, but a joiner that mistypes uses up the code.
- **Hard links in shares** (see below) aren't detected.
- **Timing with a remembered address.** A connection that tries a remembered address first takes about 0.7 s longer. This depends on the sender's own history, not on whether you're hidden or offline.
- **A hide takes up to a second.** Hiding a device takes effect within about a second; a request already being answered in that second may still get a local-network reply.

## Current limits / roadmap

- Relayed transfers are limited by the rendezvous server's bandwidth.
- Remembered addresses help most on the same network, with public IPs or IPv6, or with a port forward. Behind typical home routers an unannounced connection is usually blocked, so the server is still needed there.
- IPv4 only for now.
- Local-network discovery uses broadcast, so it covers a single subnet and doesn't cross routers or VLANs.
- The DHT library has no strict client-only mode: on a network with no firewall in the way (or with a UPnP mapping), its node may start answering other DHT nodes' queries while it runs. It never stores or serves FilePigeon data that way, but it is extra traffic; keep DHT discovery off if that matters to you.
- Hard links inside a shared folder that point at files outside it are not detected; only share folders whose contents you control.
- `serve` runs in a terminal. Running it as a Windows service needs a different way to show prompts.
