// The invite is in the part after '#', which browsers never send to this
// web server. It's read here and only ever handed to the FilePigeon app.
(function () {
  const raw = decodeURIComponent(location.hash.slice(1)).trim().toLowerCase();
  const match = /^([a-z0-9.-]+\.[a-z]{2,}(?::\d{1,5})?)\/([a-z]+(?:-[a-z]+){4})$/.exec(raw);
  if (!match) {
    document.getElementById("broken").hidden = false;
    return;
  }
  const [, host, words] = match;
  document.getElementById("open").href = `filepigeon://join/${host}/${words}`;
  document.getElementById("code").textContent = `${host} · ${words}`;
  document.getElementById("copy").onclick = () => {
    navigator.clipboard.writeText(`${host} ${words}`).then(() => {
      document.getElementById("copy").textContent = "Copied";
    });
  };
  document.getElementById("invite").hidden = false;
})();
