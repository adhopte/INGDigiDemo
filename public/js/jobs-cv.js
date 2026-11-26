/* Progressive enhancement for the CV step: upload the chosen file as the raw request body, then enable "continue". */
(function () {
  var box = document.getElementById('cv-box');
  var input = document.getElementById('cv-file');
  if (!box || !input || !window.fetch) return;
  var status = document.getElementById('cv-status');
  var next = document.getElementById('cv-continue');
  var need = document.getElementById('cv-need');
  var msg = function (k, v) { var s = box.getAttribute('data-msg-' + k) || ''; Object.keys(v || {}).forEach(function (n) { s = s.split('{' + n + '}').join(v[n]); }); return s; };
  input.addEventListener('change', function () {
    var f = input.files && input.files[0];
    if (!f) return;
    if (f.size > Number(box.getAttribute('data-max'))) { status.textContent = msg('err'); return; }
    status.textContent = msg('busy');
    fetch(box.getAttribute('data-upload'), { method: 'POST', credentials: 'same-origin', headers: { 'X-Filename': encodeURIComponent(f.name), 'Content-Type': 'application/octet-stream' }, body: f })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (r) {
        status.textContent = msg('ok', { name: r.name, size: Math.max(1, Math.round(r.size / 1000)) + ' KB' });
        if (next) { next.classList.remove('is-disabled'); next.removeAttribute('aria-disabled'); }
        if (need) need.hidden = true;
      })
      .catch(function () { status.textContent = msg('err'); });
  });
  if (next) next.addEventListener('click', function (e) { if (next.getAttribute('aria-disabled') === 'true') e.preventDefault(); });
})();
