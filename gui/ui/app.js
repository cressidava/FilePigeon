// FilePigeon main window. Plain JS, no build step.
// Everything that came from a peer (names, file names) goes through esc().

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const S = { snap: null, view: "devices", transfers: new Map(), logs: [], online: false, status: null, dnd: "auto", quiet: false, approvals: [] };

// ---------- helpers ----------
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function human(n) {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${u[i]}`;
}
const clock = (t) => new Date(t * 1000).toLocaleTimeString();
const initials = (name) => esc((name.trim()[0] || "?").toUpperCase());

const ICON = {
  up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>',
  down: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>',
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/></svg>',
  send: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2 11 13M22 2l-7 20-4-9-9-4z"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>',
  dl: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>',
};

function toast(kind, text, ms = 5000) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = text;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), ms);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    toast("error", String(e));
    throw e;
  }
}

// ---------- modal ----------
function modal({ title, body, footer = "", wide = false, onClose }) {
  const root = $("#modal-root");
  root.innerHTML = `<div class="overlay"><div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true">
    <header><h2>${esc(title)}</h2><button class="btn ghost small" data-close aria-label="Close">✕</button></header>
    <div class="body">${body}</div>${footer ? `<footer>${footer}</footer>` : ""}</div></div>`;
  const close = () => { root.innerHTML = ""; document.removeEventListener("keydown", onKey); onClose?.(); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  $$("[data-close]", root).forEach((b) => (b.onclick = close));
  $(".overlay", root).addEventListener("mousedown", (e) => { if (e.target.classList.contains("overlay")) close(); });
  return { el: $(".modal", root), close };
}

function confirmModal(title, text, okLabel, danger = false) {
  return new Promise((resolve) => {
    let done = false;
    const m = modal({
      title,
      body: `<p>${esc(text)}</p>`,
      footer: `<button class="btn" data-close>Cancel</button><button class="btn ${danger ? "danger" : "primary"}" id="m-ok">${esc(okLabel)}</button>`,
      onClose: () => { if (!done) resolve(false); },
    });
    $("#m-ok", m.el).onclick = () => { done = true; m.close(); resolve(true); };
  });
}

// ---------- status / chrome ----------
function renderChrome() {
  const st = $("#status"), txt = $("#status-text");
  st.className = "status";
  const s = S.status?.state;
  const set = S.snap?.settings;
  st.title = "";
  if (s === "setup") { st.classList.add("setup"); txt.textContent = "Setup needed"; }
  else if (s === "error") { st.classList.add("error"); txt.textContent = "Not running"; st.title = S.status.message; }
  else if (set?.invisible) { st.classList.add("invisible"); txt.textContent = "Invisible"; st.title = "Nobody can find or connect to you"; }
  else if (s === "running" && !set?.rendezvous) { st.classList.add("local"); txt.textContent = "Local network"; st.title = "Paired devices on your network can reach you (no internet server set)"; }
  else if (S.online) { st.classList.add("online"); txt.textContent = "Online"; st.title = "Paired devices can reach you"; }
  else if (s === "running") { txt.textContent = "Connecting…"; }
  else { txt.textContent = s === "stopped" ? "Stopped" : "Starting…"; }
  const inv = $("#invisible");
  if (inv) { inv.checked = !!set?.invisible; inv.disabled = !S.snap?.configured; }

  const me = S.snap;
  $("#me").innerHTML = me?.configured
    ? `<strong>${esc(me.settings.device_name)}</strong><span class="mono">${esc(me.device_id || "")}</span>`
    : "";
  $$("#dnd [data-dnd]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.dnd === S.dnd)));
  $("#dnd-now").classList.toggle("hidden", !S.quiet);
  const rb = $("#badge-requests");
  rb.textContent = S.approvals.length;
  rb.classList.toggle("hidden", S.approvals.length === 0);
  const active = [...S.transfers.values()].filter((t) => t.state === "running").length;
  const b = $("#badge-transfers");
  b.textContent = active;
  b.classList.toggle("hidden", active === 0);
  $$("#nav button").forEach((btn) => btn.classList.toggle("active", btn.dataset.view === S.view));
}

function setView(v) { S.view = v; render(); }

function render() {
  renderChrome();
  const main = $("#main");
  const views = { devices: viewDevices, requests: viewRequests, transfers: viewTransfers, shares: viewShares, activity: viewActivity, settings: viewSettings };
  // Refreshes (window focus, status changes) must not throw away what the
  // user is typing into Settings.
  const draft = S.view === "settings" ? settingsDraft() : null;
  main.innerHTML = "";
  views[S.view](main);
  if (draft) restoreSettingsDraft(draft);
}

// Settings that apply immediately (autostart, do not disturb) aren't drafts.
const DRAFT_SKIP = new Set(["autostart", "dnd"]);
function settingsDraft() {
  const form = $("#form");
  if (!form || !form.dataset.dirty) return null;
  return [...form.elements].filter((el) => el.name && !DRAFT_SKIP.has(el.name))
    .map((el) => [el.name, el.type === "checkbox" ? el.checked : el.value]);
}
function restoreSettingsDraft(draft) {
  const form = $("#form");
  if (!form) return;
  for (const [name, value] of draft) {
    const el = form.elements[name];
    if (!el) continue;
    if (el.type === "checkbox") el.checked = value; else el.value = value;
  }
  form.dataset.dirty = "1";
}

async function reload() {
  S.snap = await invoke("get_state");
  S.status = S.snap.status;
  S.online = S.snap.online;
  S.logs = S.snap.logs;
  S.transfers = new Map(S.snap.transfers.map((t) => [t.id, t]));
  S.dnd = S.snap.dnd;
  S.quiet = S.snap.quiet;
  S.approvals = S.snap.approvals;
  if (!S.snap.configured && S.view === "devices") S.view = "settings";
  render();
}

function setupBanner() {
  if (S.status?.state === "error") {
    return `<div class="banner error"><div><strong>FilePigeon isn't running</strong>${esc(S.status.message)}</div>
      <button class="btn small" id="retry" style="margin-left:auto">Retry</button></div>`;
  }
  if (S.status?.state === "setup") {
    return `<div class="banner warn"><div><strong>Finish setting up</strong>Name this PC in Settings to start FilePigeon.</div></div>`;
  }
  return "";
}
function wireBanner(root) {
  const r = $("#retry", root);
  if (r) r.onclick = () => call("restart_service");
}

// The courier illustration is bundled locally and works offline.
function courierIntro(first = false) {
  return `<section class="courier-intro ${first ? "welcome" : ""}">
    <div class="courier-copy"><span class="eyebrow">${first ? "Meet your file courier" : "Special delivery"}</span>
      <h2>Files, delivered.</h2>
      <p>${first ? "Give this PC a name, then pair another device. Your pigeon takes it from there." : "Across the room or across the internet. A little pigeon, carrying your files straight to their next home."}</p>
      <span class="courier-caption">Direct connection · End-to-end encrypted</span>
    </div><img class="courier-art" src="pigeon-courier.png" alt="A pigeon in flight carrying files in a courier satchel.">
  </section>`;
}

function courierEmpty(title, text, action = "") {
  return `<div class="card empty courier-empty"><img src="pigeon-mark.png" alt=""><h2>${title}</h2><p>${text}</p>${action}</div>`;
}

// ---------- Devices ----------
function viewDevices(root) {
  const peers = S.snap.peers;
  root.innerHTML = `${setupBanner()}${waitingBanner()}${courierIntro()}
    <div class="view-head"><h1>Your devices</h1><div class="spacer"></div>
      <button class="btn" id="have-invite">I have an invite</button>
      <button class="btn primary" id="add-friend">${ICON.link}Add a friend</button></div>
    <p class="lede">Pair once. Send whenever. You approve incoming files and requests unless auto-accept is on. <a href="#" id="pair">Pair a PC next to you</a></p>
    ${peers.length === 0 ? `<div class="card first-device"><div class="postmark">${ICON.link}</div><div><h2>Where are we flying?</h2>
        <p>Invite a friend, or open the invite someone sent you.</p></div>
        <button class="btn" id="pair2">Add a friend ${ICON.link}</button></div>
        <div class="delivery-steps"><span><b>01</b> Pair your PCs</span><span><b>02</b> Pick your files</span><span><b>03</b> Send them flying</span></div>` : ""}
    <div class="grid">${peers.map(peerCard).join("")}</div>`;
  wireBanner(root);
  $("#review", root)?.addEventListener("click", () => setView("requests"));
  $("#pair", root).onclick = (e) => { e.preventDefault(); openPairModal(); };
  $("#add-friend", root).onclick = () => openAddFriend();
  $("#pair2", root)?.addEventListener("click", () => openAddFriend());
  $("#have-invite", root).onclick = () => openJoin();
  for (const card of $$(".peer", root)) {
    const peer = peers.find((p) => p.device_id === card.dataset.id);
    card.querySelector("[data-act=files]").onclick = () => call("send_pick", { peer: peer.name, folder: false }).then((ok) => ok && setView("transfers"));
    card.querySelector("[data-act=folder]").onclick = () => call("send_pick", { peer: peer.name, folder: true }).then((ok) => ok && setView("transfers"));
    card.querySelector("[data-act=browse]").onclick = () => openBrowse(peer.name);
    card.querySelector("[data-act=rename]").onclick = () => renamePeer(peer);
    card.querySelector("[data-act=unpair]").onclick = () => unpair(peer);
    card.querySelector("[data-perm=browse]").onchange = (e) => updatePeer(peer, { allow_browse: e.target.checked });
    card.querySelector("[data-perm=hidden]").onchange = (e) => updatePeer(peer, { hidden: e.target.checked });
    // Turning auto-accept on is confirmed by a native Windows dialog from the
    // app itself, which this page can't click or skip.
    card.querySelector("[data-perm=auto]").onchange = (e) => updatePeer(peer, { auto_accept: e.target.checked });
  }
}

function peerCard(p) {
  return `<div class="card peer" data-id="${esc(p.device_id)}">
    <div class="peer-head"><div class="avatar">${initials(p.name)}</div>
      <div><div class="peer-name">${esc(p.name)}</div><div class="mono muted">${esc(p.device_id)}</div>
        ${p.hidden ? `<div class="peer-hidden">You appear offline to them</div>` : ""}</div></div>
    <div class="peer-actions">
      <button class="btn primary small" data-act="files">${ICON.send}Send files</button>
      <button class="btn small" data-act="folder">${ICON.folder}Send folder</button>
      <button class="btn small" data-act="browse">${ICON.eye}Browse their shares</button>
    </div>
    <div class="peer-perms">
      <label class="switch"><input type="checkbox" data-perm="browse" ${p.allow_browse ? "checked" : ""}>Can browse and request from my shared folders</label>
      <label class="switch warn"><input type="checkbox" data-perm="auto" ${p.auto_accept ? "checked" : ""}>Auto-accept (skip approval pop-ups)</label>
      <label class="switch"><input type="checkbox" data-perm="hidden" ${p.hidden ? "checked" : ""}>Appear offline to this device</label>
    </div>
    <div class="peer-foot"><button class="btn ghost small" data-act="rename">Rename</button><button class="btn ghost small danger" data-act="unpair">Unpair</button></div>
  </div>`;
}

async function updatePeer(p, changes) {
  const next = { deviceId: p.device_id, name: p.name, allowBrowse: p.allow_browse, autoAccept: p.auto_accept, hidden: !!p.hidden };
  if ("hidden" in changes) next.hidden = changes.hidden;
  if ("allow_browse" in changes) next.allowBrowse = changes.allow_browse;
  if ("auto_accept" in changes) next.autoAccept = changes.auto_accept;
  if ("name" in changes) next.name = changes.name;
  try { await call("peer_update", next); } finally { await reload(); }
}

function renamePeer(p) {
  const m = modal({
    title: "Rename device",
    body: `<label class="field"><span>Name</span><input type="text" id="r-name" maxlength="64" value="${esc(p.name)}"></label>`,
    footer: `<button class="btn" data-close>Cancel</button><button class="btn primary" id="r-ok">Save</button>`,
  });
  const input = $("#r-name", m.el);
  input.focus(); input.select();
  const save = async () => { await updatePeer(p, { name: input.value }); m.close(); };
  $("#r-ok", m.el).onclick = save;
  input.onkeydown = (e) => { if (e.key === "Enter") save(); };
}

async function unpair(p) {
  if (!(await confirmModal(`Unpair ${p.name}?`, `${p.name} will no longer be able to connect to you, and you won't be able to reach it until you pair again.`, "Unpair", true))) return;
  const warning = await call("peer_unpair", { deviceId: p.device_id });
  toast("ok", `Unpaired ${p.name}.`);
  if (warning) toast("warn", warning);
  reload();
}

// ---------- Pairing ----------
// Three ways in, each with one job:
//   Add a friend      -> make an invite (link + short code) to send them
//   I have an invite  -> paste/click an invite; works on a brand-new install
//   Pair a nearby PC  -> the classic show-a-code / type-a-code, no server needed
let pairUnlisten = null;

const looksLikeInvite = (t) => /filepigeon:\/\/|#|[a-z0-9-]+\.[a-z]{2,}/i.test(t);

// --- Add a friend
async function openAddFriend() {
  if (!S.snap?.configured) { openJoin(); return; }
  const hasServer = !!S.snap.settings.rendezvous;
  const m = modal({
    title: "Add a friend",
    body: hasServer ? `
      <p class="muted" style="margin-top:0">Make an invite and send it to them any way you like. When they open it, you'll get a pop-up to let them in.</p>
      <div class="row"><input type="text" id="inv-name" maxlength="36" placeholder="Who is it for? e.g. Sam"><button class="btn primary" id="inv-make">Create invite</button></div>
      <div id="inv-out"></div>
      <div id="inv-pending-wrap" hidden><h3 class="minor">Waiting to be used</h3><div id="inv-pending"></div></div>
      <p class="muted small-link"><a href="#" id="go-nearby">Pairing a PC that's right next to you? Use a pairing code instead.</a></p>`
    : `
      <div class="banner warn" style="margin-top:0"><div><strong>Inviting friends far away needs your rendezvous server.</strong>Set it up under Settings first.</div></div>
      <p class="muted small-link"><a href="#" id="go-nearby">Pair a PC on your own network with a pairing code instead.</a></p>`,
  });
  $("#go-nearby", m.el).onclick = (e) => { e.preventDefault(); m.close(); openPairModal(); };
  if (!hasServer) return;

  const showInvite = (inv, out) => {
    out.innerHTML = `<div class="invite-card">
        <div class="invite-step"><b>1</b> Send them this message (Discord, text, email…):</div>
        <textarea class="invite-text" readonly rows="6" spellcheck="false"></textarea>
        <div class="row"><button class="btn primary" id="copy-msg">Copy message</button><button class="btn" id="copy-link">Copy link only</button></div>
        <div class="invite-step"><b>2</b> When they open it, a pop-up asks you to let them in. Compare the check words with them, then click <b>Pair</b>.</div>
        <p class="muted" style="margin:0">Their code, if they'd rather type it: <span class="mono selectable">${esc(inv.code)}</span><br>
        It works once, for 24 hours. Keep FilePigeon running until they use it.</p></div>`;
    $("textarea", out).value = inv.message;
    $("#copy-msg", out).onclick = () => navigator.clipboard.writeText(inv.message).then(() => toast("ok", "Message copied. Paste it to your friend."));
    $("#copy-link", out).onclick = () => navigator.clipboard.writeText(inv.link).then(() => toast("ok", "Link copied."));
  };
  const loadPending = async () => {
    let list;
    try { list = await invoke("invite_links_pending"); } catch (_) { return; }
    $("#inv-pending-wrap", m.el).hidden = !list.length;
    const now = Date.now() / 1000;
    $("#inv-pending", m.el).innerHTML = list.map((p, n) => `<div class="row" style="margin:4px 0"><bdi>${esc(p.friend)}</bdi>
      <span class="muted">expires in ${Math.max(1, Math.round((p.expires - now) / 3600))} h</span>
      <button class="btn ghost small" data-show="${n}" style="margin-left:auto">Show</button>
      <button class="btn ghost small danger" data-cancel="${n}">Cancel</button></div>`).join("");
    $$("[data-show]", m.el).forEach((b) => (b.onclick = () => showInvite(list[+b.dataset.show], $("#inv-out", m.el))));
    $$("[data-cancel]", m.el).forEach((b) => (b.onclick = async () => {
      try { await invoke("invite_link_cancel", { slot: list[+b.dataset.cancel].slot }); toast("ok", "Invite cancelled. It won't work any more."); }
      catch (e) { toast("error", String(e)); }
      $("#inv-out", m.el).innerHTML = "";
      loadPending();
    }));
  };
  const make = async () => {
    const name = $("#inv-name", m.el).value.trim();
    if (!name) { $("#inv-name", m.el).focus(); return; }
    const out = $("#inv-out", m.el);
    out.innerHTML = `<p><span class="spinner"></span> Creating invite…</p>`;
    try {
      showInvite(await invoke("invite_link_create", { name }), out);
      $("#inv-name", m.el).value = "";
      loadPending();
    } catch (e) { out.innerHTML = `<div class="banner error" style="margin:8px 0 0"><div>${esc(e)}</div></div>`; }
  };
  $("#inv-make", m.el).onclick = make;
  $("#inv-name", m.el).onkeydown = (e) => { if (e.key === "Enter") make(); };
  $("#inv-name", m.el).focus();
  loadPending();
}

// --- I have an invite (also opened by clicking an invite link)
async function openJoin(prefill = "") {
  const fresh = !S.snap?.configured;
  const m = modal({
    title: "Join with an invite",
    body: `<div id="join-form">
        ${fresh ? `<label class="field"><span>Name this PC</span><input type="text" id="j-name" maxlength="64" value="${esc(S.snap?.settings?.device_name || "")}"><small>Your friend sees this name.</small></label>` : ""}
        <label class="field"><span>Invite</span><input type="text" id="j-code" spellcheck="false" autocomplete="off" placeholder="Paste the link or message, or type the code"></label>
        <div id="j-preview" class="muted"></div>
        <div class="row" style="justify-content:flex-end"><button class="btn primary" id="j-go">Join</button></div>
      </div>
      <div id="join-progress" hidden></div>`,
    onClose: () => { invoke("pair_cancel"); pairUnlisten?.(); pairUnlisten = null; },
  });
  const code = $("#j-code", m.el);
  code.value = prefill;
  const preview = async () => {
    const t = code.value.trim();
    if (!t) { $("#j-preview", m.el).textContent = ""; return; }
    try { const p = await invoke("invite_preview", { text: t }); $("#j-preview", m.el).innerHTML = `Invite to <strong>${esc(p.address)}</strong> · <span class="mono">${esc(p.words)}</span>`; }
    catch (e) { $("#j-preview", m.el).innerHTML = `<span style="color:var(--danger)">${esc(e)}</span>`; }
  };
  code.oninput = preview;
  preview();
  (fresh ? $("#j-name", m.el) : code).focus();

  const progress = $("#join-progress", m.el);
  const step = (html) => { $("#join-form", m.el).hidden = true; progress.hidden = false; progress.innerHTML = html; };
  pairUnlisten?.();
  pairUnlisten = await listen("join", (e) => {
    const ev = e.payload;
    if (ev.stage === "connecting") step(`<p><span class="spinner"></span> Connecting to your friend… (this takes a few seconds)</p>`);
    else if (ev.stage === "check") step(`<p>Almost there. Tell your friend these <strong>check words</strong>. Their screen shows the same ones; once they click <strong>Pair</strong>, you're connected.</p>
        <div class="code check">${esc(ev.words)}</div>
        <p class="muted row"><span class="spinner"></span> Waiting for your friend to accept…</p>`);
    else if (ev.stage === "done") { m.close(); paired(ev.result); }
    else if (ev.stage === "error") {
      step(`<div class="banner error" style="margin:0"><div>${esc(ev.message)}</div></div><div class="row" style="justify-content:flex-end;margin-top:10px"><button class="btn" id="j-back">Back</button></div>`);
      $("#j-back", m.el).onclick = () => { progress.hidden = true; $("#join-form", m.el).hidden = false; };
    }
  });
  const go = async () => {
    const text = code.value.trim();
    if (!text) { code.focus(); return; }
    const name = fresh ? $("#j-name", m.el).value.trim() : null;
    if (fresh && !name) { $("#j-name", m.el).focus(); return; }
    try { await invoke("join_invite", { text, deviceName: name }); }
    catch (e) { step(`<div class="banner error" style="margin:0"><div>${esc(e)}</div></div>`); }
  };
  $("#j-go", m.el).onclick = go;
  code.onkeydown = (e) => { if (e.key === "Enter") go(); };
}

// --- Pair a nearby PC (codes; works without any server)
async function openPairModal() {
  if (!S.snap?.configured) { toast("warn", "Name this PC in Settings first."); setView("settings"); return; }
  const m = modal({
    title: "Pair a PC nearby",
    body: `<p class="muted" style="margin-top:0">For your own PCs, or a friend sitting next to you: one PC shows a code, the other types it in. Works on your local network without any server. A code works once and expires after 10 minutes.</p>
      <div class="pair-cols">
        <div class="pair-box"><h3>Show a code</h3><p class="muted" style="margin:0">Then type it on the other PC.</p>
          <div id="host-area"><button class="btn primary" id="host">Create code</button></div></div>
        <div class="pair-box"><h3>Enter a code</h3><p class="muted" style="margin:0">From the other PC's screen.</p>
          <input type="text" id="code" placeholder="e.g. 42-river-falcon-lotus" spellcheck="false" autocomplete="off">
          <button class="btn primary" id="join">Pair</button><div id="join-msg" class="muted"></div></div>
      </div>`,
    onClose: () => { invoke("pair_cancel"); pairUnlisten?.(); pairUnlisten = null; },
  });
  pairUnlisten?.();
  pairUnlisten = await listen("pair", (e) => {
    const area = $("#host-area", m.el);
    if (!area) return;
    const ev = e.payload;
    if (ev.stage === "code") {
      area.innerHTML = `<div class="code" id="the-code">${esc(ev.code)}</div>
        <div class="row" style="margin-top:8px"><span class="spinner"></span><span class="muted">Waiting for the other PC…</span>
        <button class="btn small" id="copy" style="margin-left:auto">Copy</button></div>`;
      $("#copy", area).onclick = () => navigator.clipboard.writeText(ev.code).then(() => toast("ok", "Code copied."));
    } else if (ev.stage === "done") {
      m.close();
      paired(ev.result);
    } else if (ev.stage === "error") {
      area.innerHTML = `<div class="banner error" style="margin:0"><div>${esc(ev.message)}</div></div>
        <button class="btn" id="host">Try again</button>`;
      $("#host", area).onclick = startHost;
    }
  });
  const startHost = async () => {
    $("#host-area", m.el).innerHTML = `<span class="spinner"></span>`;
    try { await invoke("pair_host", { giveServer: false }); }
    catch (e) {
      $("#host-area", m.el).innerHTML = `<div class="banner error" style="margin:0"><div>${esc(e)}</div></div><button class="btn" id="host">Try again</button>`;
      $("#host", m.el).onclick = startHost;
    }
  };
  $("#host", m.el).onclick = startHost;
  const join = async () => {
    const text = $("#code", m.el).value.trim();
    if (!text) return;
    // An invite pasted here: hand it to the invite flow (it shows check words).
    if (looksLikeInvite(text)) { m.close(); openJoin(text); return; }
    const msg = $("#join-msg", m.el);
    msg.innerHTML = `<span class="spinner"></span> Pairing…`;
    try {
      const result = await invoke("pair_join", { code: text, giveServer: false });
      m.close();
      paired(result);
    } catch (e) { msg.innerHTML = `<span style="color:var(--danger)">${esc(e)}</span>`; }
  };
  $("#join", m.el).onclick = join;
  $("#code", m.el).onkeydown = (e) => { if (e.key === "Enter") join(); };
}

function paired({ peer, notes }) {
  reload();
  modal({
    title: "Paired",
    body: `<p>You're now paired with <strong><bdi>${esc(peer.name)}</bdi></strong>. They appear under Devices.</p>
      ${(notes || []).map((n) => `<p class="muted">${esc(n)}</p>`).join("")}
      <p class="muted">To send them files, use <strong>Send files</strong> on their card, or drag files onto this window.</p>`,
    footer: `<button class="btn primary" data-close>Done</button>`,
  });
}

// ---------- Browse ----------
function openBrowse(peerName) {
  let path = "";
  const m = modal({ title: `${peerName}'s shared folders`, wide: true, body: `<div id="crumbs" class="crumbs"></div><div id="listing" class="card list"></div>` });
  const load = async () => {
    const parts = path ? path.split("/") : [];
    $("#crumbs", m.el).innerHTML = [`<button data-i="-1">Shares</button>`, ...parts.map((p, i) => `<span class="muted">/</span><button data-i="${i}">${esc(p)}</button>`)].join("");
    $$("#crumbs button", m.el).forEach((b) => (b.onclick = () => { const i = +b.dataset.i; path = parts.slice(0, i + 1).join("/"); load(); }));
    const listing = $("#listing", m.el);
    listing.innerHTML = `<div class="empty"><span class="spinner"></span> Connecting to ${esc(peerName)}…</div>`;
    let entries;
    try { entries = await invoke("browse", { peer: peerName, path }); }
    catch (e) { listing.innerHTML = `<div class="empty"><h2>Couldn't browse</h2><p>${esc(e)}</p></div>`; return; }
    if (entries.length === 0) {
      listing.innerHTML = `<div class="empty">${path ? "This folder is empty." : `${esc(peerName)} hasn't shared any folders.`}</div>`;
      return;
    }
    listing.innerHTML = entries.map((e, i) => `<div class="list-row ${e.is_dir ? "clickable" : ""}" data-i="${i}">
        ${e.is_dir ? ICON.folder : ICON.file}<div class="grow"><div>${esc(e.name)}</div></div>
        <span class="muted">${e.is_dir ? "" : human(e.size)}</span>
        <button class="btn small" data-get="${i}">${ICON.dl}Download</button></div>`).join("");
    $$(".list-row", listing).forEach((row) => {
      const e = entries[+row.dataset.i];
      const full = path ? `${path}/${e.name}` : e.name;
      row.onclick = (ev) => {
        if (ev.target.closest("[data-get]")) return;
        if (e.is_dir) { path = full; load(); }
      };
      $("[data-get]", row).onclick = async () => {
        await call("fetch", { peer: peerName, path: full });
        toast("ok", `Asked ${peerName} for "${e.name}". They need to approve it.`);
      };
    });
  };
  load();
}

// ---------- Do not disturb + Requests ----------
async function setDnd(mode) {
  S.dnd = mode;
  renderChrome();
  await call("set_dnd", { mode });
}

function waitingBanner() {
  const n = S.approvals.length;
  if (!n) return "";
  return `<div class="banner warn"><div><strong>${n} request${n === 1 ? "" : "s"} waiting for you</strong>
    ${S.approvals.every((r) => r.approval.kind === "pair") ? "Someone used your invite and wants to pair with you." : "Someone wants to send you files, download from your shares, or pair with you."}</div>
    <button class="btn small" id="review" style="margin-left:auto">Review</button></div>`;
}

function viewRequests(root) {
  const items = S.approvals;
  root.innerHTML = `<div class="view-head"><h1>Requests</h1></div>
    <p class="lede">Incoming files and requests for your shared folders wait here for your OK, including any that arrived while do not disturb was on.</p>
    ${items.length === 0 ? courierEmpty("No deliveries at the door", `Incoming files and file requests will wait here for your approval${S.dnd === "on" ? "." : " and appear as pop-ups when do not disturb is off."}`) : ""}
    <div class="transfers">${items.map(requestCard).join("")}</div>`;
  $$("[data-answer]", root).forEach((b) => (b.onclick = async () => {
    $$(`[data-id="${b.dataset.id}"]`, root).forEach((x) => (x.disabled = true));
    await call("approval_answer", { id: Number(b.dataset.id), accept: b.dataset.answer === "yes" });
  }));
}

function requestCard(r) {
  const a = r.approval;
  const fetch = a.kind === "fetch";
  const pair = a.kind === "pair";
  const who = `<strong><bdi>${esc(a.peer)}</bdi></strong> <span class="mono muted">[${esc(a.peer_id)}]</span>`;
  const head = pair ? `${who} wants to pair with you`
             : fetch ? `${who} wants files from your share <span class="mono"><bdi>${esc(a.path)}</bdi></span>`
                     : `${who} wants to send you files`;
  const more = a.file_count - Math.min(a.files.length, 6);
  const detail = pair
    ? `<p>Using the invite you made for <strong><bdi>${esc(a.path)}</bdi></strong>. Check words: <strong class="mono">${esc(a.check || "")}</strong>. Only accept if your friend sees the same words.</p>`
    : `<p>${a.file_count} file${a.file_count === 1 ? "" : "s"}, ${human(a.total)}</p>`;
  return `<div class="card request">
    <div class="request-head"><div class="avatar">${initials(a.peer)}</div>
      <div class="grow"><div>${head}</div>${detail}</div></div>
    ${pair ? "" : `<div class="files">${a.files.slice(0, 6).map((f) => `<div>${esc(f.path)} <span>(${human(f.size)})</span></div>`).join("")}${more > 0 ? `<div>…and ${more} more</div>` : ""}</div>`}
    <div class="request-foot"><span class="muted" data-left="${r.id}">${countdown(r.seconds_left)}</span>
      <button class="btn" data-answer="no" data-id="${r.id}">Deny</button>
      <button class="btn primary" data-answer="yes" data-id="${r.id}">${pair ? "Pair" : fetch ? "Allow" : "Accept"}</button></div></div>`;
}

const countdown = (s) => `Denies automatically in ${s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`}`;

function tickRequests() {
  for (const r of S.approvals) {
    r.seconds_left = Math.max(0, r.seconds_left - 1);
    const el = document.querySelector(`[data-left="${r.id}"]`);
    if (el) el.textContent = countdown(r.seconds_left);
  }
}

// ---------- Transfers ----------
function viewTransfers(root) {
  const list = [...S.transfers.values()].sort((a, b) => b.id - a.id);
  root.innerHTML = `<div class="view-head"><h1>Transfers</h1><div class="spacer"></div>
      <button class="btn" id="open-dl">${ICON.folder}Downloads folder</button>
      <button class="btn" id="clear" ${list.some((t) => t.state !== "running") ? "" : "disabled"}>Clear finished</button></div>
    ${list.length === 0 ? courierEmpty("Ready for the next flight", "Send files from Devices, or drag them onto this window.", `<button class="btn" id="go-devices">Choose a device ${ICON.link}</button>`) : ""}
    <div class="transfers" id="tlist">${list.map(transferCard).join("")}</div>`;
  $("#open-dl", root).onclick = () => call("open_downloads_cmd");
  $("#clear", root).onclick = async () => { await call("clear_finished"); reload(); };
  $("#go-devices", root)?.addEventListener("click", () => setView("devices"));
}

function transferCard(t) {
  const pct = t.total ? Math.min(100, (t.done * 100) / t.total) : 100;
  const label = { running: "In flight", done: "Delivered", failed: "Failed" }[t.state];
  const extra = t.state === "running" ? `${human(t.bytes_per_sec)}/s` : esc(t.message || "");
  return `<div class="card transfer ${t.state}" id="t-${t.id}">
    <div class="dir">${t.direction === "send" ? ICON.up : ICON.down}</div>
    <div class="title">${esc(t.name)}</div><span class="pill ${t.state}">${label}</span>
    <div class="bar"><i style="width:${pct.toFixed(1)}%"></i></div>
    <div class="meta"><span>${t.direction === "send" ? "to" : "from"} ${esc(t.peer)}</span>
      <span>${human(t.done)} / ${human(t.total)}</span><span>${extra}</span></div></div>`;
}

// ---------- Shares ----------
function viewShares(root) {
  const shares = S.snap.shares;
  root.innerHTML = `<div class="view-head"><h1>Shared folders</h1></div>
    <p class="lede">Paired devices that you allow can browse these folders and request files from them. Sharing is read-only, and every request still needs your approval unless auto-accept is on for that device.</p>
    <div class="card list" style="margin-bottom:18px">
      ${shares.length === 0 ? `<div class="empty">Nothing shared yet.</div>` : shares.map((s) => `<div class="list-row">${ICON.folder}
        <div class="grow"><div><strong>${esc(s.name)}</strong></div><div class="muted mono">${esc(s.path)}</div></div>
        <button class="btn small danger" data-rm="${esc(s.name)}">Stop sharing</button></div>`).join("")}
    </div>
    <div class="card settings"><h2>Share a folder</h2>
      <div class="row"><input type="text" id="sh-name" placeholder="Name others will see, e.g. photos" maxlength="64">
        <button class="btn primary" id="sh-add">${ICON.folder}Choose folder…</button></div></div>`;
  $$("[data-rm]", root).forEach((b) => (b.onclick = async () => {
    await call("share_remove", { name: b.dataset.rm });
    reload();
  }));
  $("#sh-add", root).onclick = async () => {
    const nameInput = $("#sh-name", root);
    const path = await call("pick_folder", { title: "Choose a folder to share" });
    if (!path) return;
    const name = nameInput.value.trim() || path.split(/[\\/]/).filter(Boolean).pop();
    await call("share_add", { name, path });
    toast("ok", `Sharing "${name}".`);
    reload();
  };
}

// ---------- Activity ----------
function viewActivity(root) {
  root.innerHTML = `<div class="view-head"><h1>Activity</h1></div>
    <div class="card log" id="log">${S.logs.length ? S.logs.map(logLine).join("") : `<div class="muted">No activity yet.</div>`}</div>`;
  const log = $("#log", root);
  log.scrollTop = log.scrollHeight;
}
const logLine = (l) => `<div class="${l.text.startsWith("[security]") ? "sec" : ""}"><time>${clock(l.time)}</time>${esc(l.text)}</div>`;

// ---------- Settings ----------
function viewSettings(root) {
  const s = S.snap.settings;
  const first = !S.snap.configured;
  root.innerHTML = `${first ? courierIntro(true) : setupBanner()}
    ${first ? `<div class="card invite-first"><div><h2>Got an invite from a friend?</h2><p class="muted" style="margin:4px 0 0">That's all you need: no server settings.</p></div>
      <button class="btn primary" id="first-join">Open my invite</button></div>
      <p class="muted" style="margin:0 0 10px">Setting up your own? Fill in the settings below.</p>` : ""}
    <div class="view-head"><h1>Settings</h1></div>
    <form class="card settings" id="form" autocomplete="off">
      <h2>This PC</h2>
      <label class="field"><span>Device name</span><input type="text" name="device_name" maxlength="64" value="${esc(s.device_name)}"><small>Shown to devices you pair with.</small></label>
      ${S.snap.device_id ? `<label class="field"><span>Device id</span><div class="mono">${esc(S.snap.device_id)}</div></label>` : ""}
      <hr><h2>Rendezvous server <span class="muted" style="font-weight:400">(optional)</span></h2>
      <p class="muted" style="margin:-6px 0 12px">Leave empty to share only on your local network. Needed to reach devices over the internet. <strong>Invited by someone?</strong> Leave this empty: pasting their invite under Devices → Pair a device sets it up for you.</p>
      <label class="field"><span>Address</span><input type="text" name="rendezvous" placeholder="pigeon.example.com:7400" value="${esc(s.rendezvous)}"></label>
      <label class="field"><span>Server key</span><input type="password" name="rendezvous_key" class="mono" autocomplete="off" spellcheck="false"
          placeholder="${s.has_server_key ? "Saved and hidden. Paste a new key only to replace it." : "128 hex characters from: pigeon-rendezvous --show-key"}">
        <small>${s.has_server_key ? "&#10003; Saved, encrypted for your Windows account. It's never shown, and the saved copy can only be read on this PC." : "Only needed on the server owner's PC. Friends get theirs automatically by pairing."}</small></label>
      <label class="field"><span>Address for friends <span class="muted" style="font-weight:400">(optional)</span></span><input type="text" name="friend_address" placeholder="Same as above" value="${esc(s.friend_address || "")}">
        <small>The address friends' PCs should use, if this PC reaches the server by a local address.</small></label>
      <label class="field"><span>Invite page <span class="muted" style="font-weight:400">(optional)</span></span><input type="text" name="invite_page" placeholder="https://fp.example.com/join" value="${esc(s.invite_page || "")}">
        <small>Your FilePigeon invite web page. Invites then carry a link your friends can just click: it offers the download and opens the invite.</small></label>
      ${s.rendezvous ? `<div class="field"><span>Friends' keys</span><div id="invites" class="muted">Friends you gave a key to your server appear here. <button type="button" class="btn small" id="load-invites">Show</button></div></div>` : ""}
      <hr><h2>Receiving</h2>
      <label class="field"><span>Save received files to</span><div class="row"><input type="text" name="download_dir" value="${esc(s.download_dir)}"><button type="button" class="btn" id="pick-dl">Browse…</button></div></label>
      <label class="field"><span>Auto-deny unanswered requests after (seconds)</span><input type="number" name="prompt_timeout_secs" min="10" max="3600" value="${s.prompt_timeout_secs}"></label>
      <hr><h2>Startup</h2>
      <label class="switch" style="margin-bottom:6px"><input type="checkbox" name="autostart" ${first || S.snap.autostart ? "checked" : ""}>Start FilePigeon when I sign in</label>
      <small class="muted" style="display:block;margin:0 0 4px 44px">It starts quietly in the tray so paired devices can reach you. ${first ? "" : "Changes here take effect immediately."}</small>
      <hr><h2>Do not disturb</h2>
      <div class="radio-list">
        <label><input type="radio" name="dnd" value="off" ${S.dnd === "off" ? "checked" : ""}><span>Off<small>Show an approval pop-up as soon as a request arrives.</small></span></label>
        <label><input type="radio" name="dnd" value="auto" ${S.dnd === "auto" ? "checked" : ""}><span>Automatic<small>Stay quiet while a full-screen app, game, or presentation is running.</small></span></label>
        <label><input type="radio" name="dnd" value="on" ${S.dnd === "on" ? "checked" : ""}><span>On<small>Never pop up.</small></span></label>
      </div>
      <small class="muted" style="display:block;margin-bottom:4px">While quiet, requests wait on the Requests page for up to 14 minutes instead of being denied. When quiet ends, anything still waiting pops up. Changes here take effect immediately.</small>
      <hr><h2>Network</h2>
      <label class="switch" style="margin-bottom:6px"><input type="checkbox" name="upnp" ${s.upnp ? "checked" : ""}>Allow temporary router port mapping (UPnP) when a direct connection needs it</label>
      <small class="muted" style="display:block;margin:0 0 14px 44px">The mapping lasts only while a transfer is active and is removed afterwards.</small>
      <label class="switch" style="margin-bottom:6px"><input type="checkbox" name="dht" ${s.dht ? "checked" : ""}>Find devices over the internet without a server (DHT, experimental)</label>
      <small class="muted" style="display:block;margin:0 0 14px 44px">Used only when no rendezvous server is set or it can't be reached. Uses the public BitTorrent DHT: your devices leave each other encrypted notes there that nobody else can read or link to you. Connecting this way can take up to a minute and doesn't work behind every router.</small>
      <label class="field"><span>UDP port</span><input type="number" name="listen_port" min="0" max="65535" value="${s.listen_port}"><small>0 picks a random port once and keeps it, so devices can reconnect to the address they remember (recommended).</small></label>
      <div class="row" style="justify-content:flex-end;margin-top:8px"><button class="btn primary" type="submit">${first ? "Save and go online" : "Save and restart"}</button></div>
    </form>`;
  wireBanner(root);
  $("#first-join", root)?.addEventListener("click", () => openJoin());
  const form = $("#form", root);
  $("#pick-dl", root).onclick = async () => {
    const p = await call("pick_folder", { title: "Where should received files go?" });
    if (p) form.download_dir.value = p;
  };
  $$("input[name=dnd]", form).forEach((r) => (r.onchange = () => setDnd(r.value)));
  form.addEventListener("input", (e) => { if (!DRAFT_SKIP.has(e.target.name)) form.dataset.dirty = "1"; });
  const loadInvites = async () => {
    const box = $("#invites", root);
    box.innerHTML = `<span class="spinner"></span>`;
    let list;
    try { list = await invoke("invites_list"); }
    catch (e) { box.innerHTML = `<span style="color:var(--danger)">${esc(e)}</span>`; return; }
    if (!list.length) { box.textContent = "No friends have a key to your server."; return; }
    box.innerHTML = list.map((i, n) => `<div class="row" style="margin:4px 0"><bdi>${esc(i.name)}</bdi>
      <span class="muted">${i.connected ? "connected" : "not connected"}</span>
      <button type="button" class="btn ghost small danger" data-n="${n}" style="margin-left:auto">Revoke</button></div>`).join("");
    $$("button[data-n]", box).forEach((b) => (b.onclick = async () => {
      const i = list[+b.dataset.n];
      if (!(await confirmModal(`Revoke ${i.name}?`, `${i.name} will no longer be able to use your server. Within a few seconds their connections close. Pairing them again with "Give this device its own key" makes a new one.`, "Revoke", true))) return;
      try { await invoke("invite_revoke", { name: i.name }); toast("ok", `Revoked ${i.name}.`); }
      catch (e) { toast("error", String(e)); }
      loadInvites();
    }));
  };
  $("#load-invites", root)?.addEventListener("click", loadInvites);
  if (!first) {
    form.autostart.onchange = async (e) => {
      try {
        await call("set_autostart", { enabled: e.target.checked });
        toast("ok", e.target.checked ? "FilePigeon will start when you sign in." : "FilePigeon won't start automatically.");
      } catch (_) { e.target.checked = !e.target.checked; }
    };
  }
  form.onsubmit = async (e) => {
    e.preventDefault();
    const settings = {
      device_name: form.device_name.value,
      rendezvous: form.rendezvous.value,
      rendezvous_key: form.rendezvous_key.value,
      friend_address: form.friend_address.value,
      invite_page: form.invite_page.value,
      download_dir: form.download_dir.value,
      upnp: form.upnp.checked,
      prompt_timeout_secs: Number(form.prompt_timeout_secs.value),
      listen_port: Number(form.listen_port.value),
      invisible: !!S.snap.settings.invisible,
      dht: form.dht.checked,
    };
    await call("save_settings", { settings });
    form.dataset.dirty = ""; // saved: the next refresh shows what's stored
    if (first) await call("set_autostart", { enabled: form.autostart.checked }).catch(() => {});
    toast("ok", "Settings saved.");
    await reload();
    if (first) setView("devices");
  };
}

// ---------- drag & drop ----------
async function setupDragDrop() {
  const webview = window.__TAURI__.webview?.getCurrentWebview?.();
  if (!webview) return;
  await webview.onDragDropEvent((e) => {
    const t = e.payload.type;
    $("#drop").classList.toggle("hidden", !(t === "enter" || t === "over"));
    if (t === "drop" && e.payload.paths?.length) chooseRecipient(e.payload.paths);
  });
}

function chooseRecipient(paths) {
  const peers = S.snap?.peers || [];
  if (peers.length === 0) { toast("warn", "Pair a device first."); return; }
  const names = paths.map((p) => p.split(/[\\/]/).pop());
  const m = modal({
    title: `Send ${paths.length} item${paths.length > 1 ? "s" : ""}`,
    body: `<p class="muted" style="margin-top:0">${esc(names.slice(0, 5).join(", "))}${names.length > 5 ? ` and ${names.length - 5} more` : ""}</p>
      <div class="card list">${peers.map((p, i) => `<div class="list-row clickable" data-i="${i}"><div class="avatar" style="width:32px;height:32px;font-size:14px">${initials(p.name)}</div>
        <div class="grow"><div><strong>${esc(p.name)}</strong></div></div>${ICON.send}</div>`).join("")}</div>`,
  });
  $$(".list-row", m.el).forEach((row) => (row.onclick = async () => {
    const peer = peers[+row.dataset.i];
    m.close();
    await call("send_paths", { peer: peer.name, paths });
    setView("transfers");
  }));
}

// ---------- events ----------
async function main() {
  $$("#nav button").forEach((b) => (b.onclick = () => setView(b.dataset.view)));
  await listen("transfer", (e) => {
    const t = e.payload;
    S.transfers.set(t.id, t);
    if (S.view === "transfers") {
      const el = document.getElementById(`t-${t.id}`);
      if (el) el.outerHTML = transferCard(t); else render();
    }
    renderChrome();
  });
  await listen("log", (e) => {
    if (e.payload.text.startsWith("Paired with")) { toast("ok", e.payload.text); reload(); }
    S.logs.push(e.payload);
    if (S.logs.length > 500) S.logs.shift();
    if (S.view === "activity") {
      const log = $("#log");
      if (log) {
        if (S.logs.length === 1) log.innerHTML = "";
        log.insertAdjacentHTML("beforeend", logLine(e.payload));
        while (log.childElementCount > 500) log.firstElementChild.remove(); // bounded, like S.logs
        log.scrollTop = log.scrollHeight;
      }
    }
  });
  await listen("status", (e) => { S.status = e.payload; if (e.payload.state !== "running") S.online = false; reload(); });
  await listen("online", (e) => { S.online = e.payload; renderChrome(); });
  await listen("toast", (e) => toast(e.payload.kind, e.payload.text));
  await listen("approvals", (e) => {
    const before = S.approvals.length;
    S.approvals = e.payload;
    if (S.view === "requests") render(); else renderChrome();
    if (S.approvals.length > before && S.quiet) toast("warn", "A request is waiting (do not disturb is on).");
  });
  await listen("dnd", (e) => { S.dnd = e.payload; if (S.view === "settings") render(); else renderChrome(); });
  await listen("quiet", (e) => { S.quiet = e.payload; renderChrome(); });
  $$("#dnd [data-dnd]").forEach((b) => (b.onclick = () => setDnd(b.dataset.dnd)));
  $("#invisible").onchange = async (e) => {
    const on = e.target.checked;
    try {
      await call("set_invisible", { invisible: on });
      toast(on ? "warn" : "ok", on ? "You're invisible. Nobody can find or connect to you." : "You're visible to your paired devices again.");
    } finally { reload(); }
  };
  await listen("invisible", () => reload());
  await listen("invite-link", async () => { const l = await invoke("take_invite_link"); if (l) openJoin(l); });
  setInterval(tickRequests, 1000);
  window.addEventListener("focus", () => { if (!$("#modal-root").innerHTML) reload(); });
  setupDragDrop();
  await reload();
  invoke("take_invite_link").then((l) => { if (l) openJoin(l); });
}

main().catch((e) => {
  document.body.innerHTML = `<pre style="padding:20px;white-space:pre-wrap">FilePigeon failed to start:\n${esc(e)}</pre>`;
});
