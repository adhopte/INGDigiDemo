/* Progressive enhancement: "Enlarge QR code" opens the same image in a large dialog (a dense QR code scans best big). */
(function () {
  var buttons = document.querySelectorAll('[data-qr-zoom]');
  if (!buttons.length || typeof HTMLDialogElement === 'undefined') return;
  Array.prototype.forEach.call(buttons, function (b) {
    var img = document.getElementById(b.getAttribute('data-qr-zoom'));
    if (!img) return;
    b.hidden = false;
    b.addEventListener('click', function () {
      var dlg = document.createElement('dialog');
      dlg.className = 'qr-dialog';
      dlg.setAttribute('aria-label', img.getAttribute('alt') || '');
      var big = document.createElement('img');
      big.className = 'qr-big'; big.src = img.src; big.alt = img.getAttribute('alt') || '';
      var close = document.createElement('button');
      close.type = 'button'; close.className = 'btn btn-secondary'; close.textContent = b.getAttribute('data-close') || 'Close';
      close.addEventListener('click', function () { dlg.close(); });
      dlg.addEventListener('close', function () { dlg.remove(); });
      dlg.appendChild(big); dlg.appendChild(close);
      document.body.appendChild(dlg); dlg.showModal();
    });
  });
})();
