// Accept/deny pop-up. Deny is focused by default and Escape denies,
// so a stray Enter or keypress never accepts a transfer.

const { invoke } = window.__TAURI__.core;
const win = window.__TAURI__.window.getCurrentWindow();
const id = Number(win.label.replace("approve-", ""));

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function human(n) {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${u[i]}`;
}

const ICONS = {
  offer: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>',
  pair: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>',
  fetch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/></svg>',
};

// Accept stays disabled until the request is on screen, and for a moment after
// the window appears or regains focus, so a click aimed at something else (or
// a pop-up appearing under the cursor) can never accept by accident.
const ARM_DELAY_MS = 1000;
let armedAt = Infinity;
function disarm() {
  armedAt = Infinity;
  const btn = document.getElementById("accept");
  btn.disabled = true;
  setTimeout(arm, ARM_DELAY_MS);
}
function arm() {
  if (loaded && !answered && document.visibilityState === "visible" && document.hasFocus()) {
    armedAt = Date.now();
    document.getElementById("accept").disabled = false;
  }
}
let loaded = false;
window.addEventListener("focus", disarm);
window.addEventListener("blur", () => { armedAt = Infinity; document.getElementById("accept").disabled = true; });
document.addEventListener("visibilitychange", disarm);
document.getElementById("accept").disabled = true;

let answered = false;
async function answer(accept) {
  if (answered) return;
  if (accept && armedAt === Infinity) return; // not armed: ignore
  answered = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try { await invoke("approval_answer", { id, accept }); } catch (_) {}
  // The app closes this window once it has the answer.
}

document.getElementById("deny").onclick = () => answer(false);
document.getElementById("accept").onclick = () => answer(true);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") answer(false); });

async function load() {
  let view;
  try {
    view = await invoke("approval_get", { id });
  } catch (e) {
    document.getElementById("title").textContent = "Request expired";
    document.getElementById("subtitle").textContent = String(e);
    document.getElementById("accept").disabled = true;
    return;
  }
  const a = view.approval;
  const fetch = a.kind === "fetch";
  const pair = a.kind === "pair";
  const icon = document.getElementById("icon");
  icon.innerHTML = pair ? ICONS.pair : fetch ? ICONS.fetch : ICONS.offer;
  icon.classList.toggle("fetch", fetch);
  // <bdi> isolates the peer's name so direction-changing characters can't
  // rearrange the rest of the sentence; the device id can't be imitated.
  const who = `<strong><bdi>${esc(a.peer)}</bdi></strong> <span class="mono muted">[${esc(a.peer_id)}]</span>`;
  document.getElementById("title").innerHTML = pair ? `${who} wants to pair with you` : fetch ? `${who} wants files from you` : `${who} wants to send you files`;
  document.getElementById("subtitle").innerHTML = pair
    ? `This PC used the invite you made for <strong><bdi>${esc(a.path)}</bdi></strong>.`
    : fetch
    ? `From your share <span class="mono"><bdi>${esc(a.path)}</bdi></span>: ${a.file_count} file${a.file_count === 1 ? "" : "s"}, ${human(a.total)}`
    : `${a.file_count} file${a.file_count === 1 ? "" : "s"}, ${human(a.total)} total`;
  const more = a.file_count - a.files.length;
  const row = (f) => `<div class="list-row">${ICONS.file}<div class="grow"><div><bdi>${esc(f.path)}</bdi></div></div><span class="muted">${human(f.size)}</span></div>`;
  const largestShown = a.largest && a.files.some((f) => f.path === a.largest.path);
  document.getElementById("files").innerHTML = pair
    ? `<div class="check-box"><div class="muted">Check words</div><div class="check-words">${esc(a.check || "")}</div>
       <div class="muted">Ask your friend which words their screen shows. Only click <b>Pair</b> if they match.</div></div>`
    : a.files.map(row).join("") +
    (more > 0 ? `<div class="list-row muted">…and ${more} more</div>` : "") +
    (a.largest && !largestShown ? `<div class="list-row muted">Largest file:</div>${row(a.largest)}` : "");
  document.getElementById("accept").textContent = pair ? "Pair" : fetch ? "Allow" : "Accept";

  let left = view.seconds_left;
  const total = Math.max(a.timeout_secs, 1);
  const tick = () => {
    document.getElementById("countdown").textContent = `Denies automatically in ${left}s`;
    document.getElementById("timer").style.width = `${(left * 100) / total}%`;
    if (left <= 0) answer(false);
    left--;
  };
  tick();
  setInterval(tick, 1000);
  document.getElementById("deny").focus();
  loaded = true;
  disarm();
}

load();
