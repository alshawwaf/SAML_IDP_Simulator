/* Reachable-address card — shared by the RADIUS + TACACS+ config pages.
   Included inside an existing <script> block. Resolves the host's public IP
   from the backend (with a manual override) and lets the operator refresh it. */
(function () {
  var card = document.getElementById('reachCard');
  if (!card) return;
  var url = card.dataset.endpointUrl;
  var hostEl = document.getElementById('reachHost');
  var srcEl = document.getElementById('reachSource');
  var btn = document.getElementById('reachRefresh');

  function paint(host, source) {
    if (host) hostEl.value = host;
    hostEl.placeholder = host ? '' : 'could not detect — set an override below';
    if (source) srcEl.textContent = source;
    document.querySelectorAll('.reach-ep').forEach(function (el) {
      el.textContent = (host || '<host>') + ':' + el.dataset.port;
    });
  }

  function load(refresh) {
    btn.disabled = true;
    var ic = btn.querySelector('i');
    if (ic) ic.classList.add('spin');
    fetch(url + (refresh ? '?refresh=1' : ''))
      .then(function (r) { return r.json(); })
      .then(function (d) { paint(d.host, d.source); })
      .catch(function () { paint(null, 'unknown'); })
      .finally(function () { btn.disabled = false; if (ic) ic.classList.remove('spin'); });
  }

  btn.addEventListener('click', function () { load(true); });
  if (!hostEl.value) load(false);   // first visit with no cached IP: detect now

  document.querySelectorAll('.copybtn').forEach(function (b) {
    b.addEventListener('click', function () {
      var t = document.querySelector(b.dataset.copy);
      var txt = t ? (t.value || t.textContent) : '';
      if (!txt || !navigator.clipboard) return;
      navigator.clipboard.writeText(txt.trim());
      var i = b.querySelector('i');
      if (i) { var old = i.className; i.className = 'bi bi-check2'; setTimeout(function () { i.className = old; }, 1200); }
    });
  });
})();
