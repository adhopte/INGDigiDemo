// Portrait upload for the admin console: shrink the chosen photo to a small JPEG in the browser and put its base64 into the hidden field.
(function () {
  var file = document.getElementById('f-portrait-file');
  var hidden = document.getElementById('f-portrait');
  var preview = document.getElementById('portrait-preview');
  var clear = document.getElementById('portrait-clear');
  if (!file || !hidden || !preview || !clear) return;
  var MAX_W = 240, MAX_H = 300, MAX_CHARS = 60000;
  function set(b64) {
    hidden.value = b64 || '';
    if (b64) { preview.src = 'data:image/jpeg;base64,' + b64; preview.hidden = false; clear.hidden = false; }
    else { preview.removeAttribute('src'); preview.hidden = true; clear.hidden = true; file.value = ''; }
  }
  clear.addEventListener('click', function () { set(''); });
  file.addEventListener('change', function () {
    var f = file.files && file.files[0];
    if (!f) return;
    var url = URL.createObjectURL(f);
    var img = new Image();
    img.onload = function () {
      var k = Math.min(1, MAX_W / img.width, MAX_H / img.height);
      var c = document.createElement('canvas');
      c.width = Math.max(1, Math.round(img.width * k)); c.height = Math.max(1, Math.round(img.height * k));
      var ctx = c.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, c.width, c.height);
      ctx.drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(url);
      var q = 0.85, out = '';
      do { out = c.toDataURL('image/jpeg', q).split(',')[1] || ''; q -= 0.15; } while (out.length > MAX_CHARS && q > 0.1);
      set(out.length <= MAX_CHARS ? out : '');
    };
    img.onerror = function () { URL.revokeObjectURL(url); set(''); };
    img.src = url;
  });
})();
