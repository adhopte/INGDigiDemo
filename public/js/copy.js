// Copy-to-clipboard for elements marked data-copy="<id of the element to copy>". Without JS the button stays hidden and the link is selectable text.
(function () {
  document.querySelectorAll('button[data-copy]').forEach(function (btn) {
    var target = document.getElementById(btn.getAttribute('data-copy'));
    if (!target || !navigator.clipboard) return;
    btn.hidden = false;
    var label = btn.textContent;
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(target.textContent || '').then(function () {
        btn.textContent = btn.getAttribute('data-done') || label;
        setTimeout(function () { btn.textContent = label; }, 2000);
      });
    });
  });
})();
