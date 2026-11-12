/* Progressive enhancement: poll the verification status and continue automatically when the wallet has responded.
   Without JavaScript the page offers a manual "continue" button (see <noscript>). */
(function () {
  var box = document.getElementById('verify-status');
  if (!box || !window.fetch) return;
  var statusUrl = box.getAttribute('data-status-url');
  var finishUrl = box.getAttribute('data-finish-url');
  var stopped = false;

  function tick() {
    if (stopped) return;
    fetch(statusUrl, { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : { status: 'unknown' }; })
      .then(function (s) {
        if (s.status === 'complete' || s.status === 'failed' || s.status === 'expired') {
          stopped = true;
          box.textContent = box.getAttribute('data-msg-done');
          window.location.assign(finishUrl);
          return;
        }
        window.setTimeout(tick, 2000);
      })
      .catch(function () { window.setTimeout(tick, 4000); });
  }
  window.setTimeout(tick, 1500);
})();
