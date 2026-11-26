/* Issuance workspace: identity -> credentials -> offer. Talks to /demo-issuer/lab/api (a thin proxy to the issuer's data API).
   No inline styles or scripts (strict CSP): all DOM is built with createElement, classes carry the styling. */
(function () {
  'use strict';
  var root = document.getElementById('lab-root');
  if (!root) return;
  var API = root.getAttribute('data-api');
  var LOCALE = root.getAttribute('data-locale') || 'en';
  var S = JSON.parse(root.getAttribute('data-i18n') || '{}');
  var tr = function (k, v) { var s = S[k] || k; if (v) Object.keys(v).forEach(function (n) { s = s.split('{' + n + '}').join(v[n]); }); return s; };

  var SHARED = { given_name: 1, family_name: 1, birth_date: 1, nationality: 1, resident_country: 1, portrait: 1 }; // provided by the identity
  var state = { step: 1, presets: [], configs: [], identity: {}, creds: [], uid: 1, caseRec: null, busy: false, error: '', loading: true, loadError: false };

  function h(tag, attrs) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === false || v === null || v === undefined) return;
      if (k === 'class') el.className = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else el.setAttribute(k, v === true ? '' : v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      (Array.isArray(c) ? c : [c]).forEach(function (x) { el.appendChild(typeof x === 'string' ? document.createTextNode(x) : x); });
    }
    return el;
  }
  function icon(path) { // simple stroke icons (no inline style)
    var ns = 'http://www.w3.org/2000/svg';
    var s = document.createElementNS(ns, 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('width', '18'); s.setAttribute('height', '18'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor'); s.setAttribute('stroke-width', '1.8'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round'); s.setAttribute('aria-hidden', 'true');
    var p = document.createElementNS(ns, 'path'); p.setAttribute('d', path); s.appendChild(p); return s;
  }
  var ICONS = {
    id: 'M4 6h16v12H4zM8 10h3M8 14h3M14 10h3M14 14h3', car: 'M5 16V11l2-5h10l2 5v5M3 16h18M7 19v-3M17 19v-3', doc: 'M7 3h8l4 4v14H7zM15 3v4h4M10 12h6M10 16h6',
    copy: 'M9 9h10v10H9zM5 15V5h10', trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3', chevron: 'M6 9l6 6 6-6', plus: 'M12 5v14M5 12h14', arrow: 'M5 12h14M13 6l6 6-6 6', back: 'M19 12H5M11 6l-6 6 6 6', user: 'M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0', close: 'M6 6l12 12M18 6L6 18'
  };
  function configIcon(c) { return c.id.indexOf('mDL') >= 0 ? ICONS.car : c.format === 'mso_mdoc' ? ICONS.id : ICONS.doc; }

  function api(path, opts) {
    return fetch(API + path, Object.assign({ credentials: 'same-origin', headers: { Accept: 'application/json' } }, opts || {})).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) {
        if (!r.ok) { var e = new Error((b && b.error && b.error.message) || tr('lab.err.generic')); e.details = b && b.error; throw e; }
        return b;
      });
    });
  }
  var toastEl = h('div', { class: 'lab-toast', role: 'status', 'aria-live': 'polite' });
  document.body.appendChild(toastEl);
  var toastTimer;
  function toast(msg) { toastEl.textContent = msg; toastEl.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 2200); }
  function copy(text) {
    var done = function () { toast(tr('lab.copied')); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, done); else done();
  }

  // ------------------------------------------------------------------ data helpers
  var cfg = function (id) { return state.configs.filter(function (c) { return c.id === id; })[0]; };
  var today = function (plusYears) { var d = new Date(); d.setFullYear(d.getFullYear() + plusYears); return d.toISOString().slice(0, 10); };
  function defaults(id) { // sensible starting values for what the issuer itself fills in
    var cc = (state.identity.resident_country || state.identity.nationality || 'FR').toUpperCase().slice(0, 2);
    var r = function (n) { return String(Math.floor(Math.random() * Math.pow(10, n))).padStart(n, '0'); };
    if (id.indexOf('pid') >= 0) return { expiry_date: today(10), issuing_country: cc };
    if (id.indexOf('mDL') >= 0) return { issue_date: today(-1), expiry_date: today(9), issuing_country: cc, issuing_authority: 'IN Groupe', document_number: 'AA' + r(5), driving_privileges: 'B', un_distinguishing_sign: cc };
    if (id.indexOf('birth_certificate') >= 0) return { birth_record_reference: 'AA' + r(9), issuance_date: today(-1), issuing_authority: 'IN Groupe' };
    return {};
  }
  function addCred(id, attrs, expanded) {
    state.creds.push({ uid: state.uid++, id: id, attrs: Object.assign({}, attrs || defaults(id)), expanded: !!expanded });
  }
  function nameOf(id) { var c = cfg(id); return c ? c.name : id; }
  function summary(c) {
    var conf = cfg(c.id); if (!conf) return '';
    var parts = [];
    conf.fields.forEach(function (f) { var v = c.attrs[f.name]; if (parts.length < 2 && v !== undefined && v !== '' && !SHARED[f.name] && f.valueType !== 'jpeg') parts.push(f.label + ': ' + v); });
    return parts.join(' · ');
  }
  function portraitSrc(b64) { return b64 ? 'data:image/jpeg;base64,' + b64 : ''; }
  function personName() { return ((state.identity.given_name || '') + ' ' + (state.identity.family_name || '')).trim(); }
  function identityReady() { return !!(state.identity.given_name && state.identity.family_name && state.identity.birth_date); }

  // ------------------------------------------------------------------ rendering
  function steps() {
    var labels = [tr('lab.step.identity'), tr('lab.step.credentials'), tr('lab.step.offer')];
    var ol = h('ol', { class: 'flow-steps lab-steps', 'aria-label': tr('lab.steps') });
    labels.forEach(function (l, i) {
      var n = i + 1;
      if (i) ol.appendChild(h('li', { class: 'sep', 'aria-hidden': 'true' }));
      ol.appendChild(h('li', { class: n === state.step ? 'current' : n < state.step ? 'done' : '', 'aria-current': n === state.step ? 'step' : false }, h('span', { class: 'num-step', 'aria-hidden': 'true' }, n < state.step ? '✓' : String(n)), l));
    });
    var wrap = h('div', { class: 'lab-stepbar' }, ol);
    if (state.step > 1 || identityReady()) wrap.appendChild(h('button', { type: 'button', class: 'lab-link', onclick: startOver }, tr('lab.start_over')));
    return wrap;
  }
  function startOver() { state.step = 1; state.identity = {}; state.creds = []; state.caseRec = null; state.error = ''; render(); }
  function errorBox() { return state.error ? h('div', { class: 'alert alert-error', role: 'alert' }, state.error) : null; }

  function field(label, input, required, id) {
    return h('div', { class: 'field' }, h('label', { for: id }, label, required ? h('span', { class: 'req', 'aria-hidden': 'true' }, ' *') : null), input);
  }
  function identityInput(name, type) {
    var id = 'idf-' + name;
    var input = h('input', { id: id, type: type || 'text', autocomplete: 'off', placeholder: type === 'date' ? '' : tr('lab.not_set'), value: state.identity[name] || '', 'aria-required': name === 'given_name' || name === 'family_name' || name === 'birth_date' ? 'true' : false,
      oninput: function (e) { state.identity[name] = e.target.value; updateContinue(); } });
    return field(tr('lab.field.' + name), input, name === 'given_name' || name === 'family_name' || name === 'birth_date', id);
  }
  var continueBtn;
  function updateContinue() { if (continueBtn) continueBtn.disabled = !identityReady(); }

  function loadPortrait(file) {
    if (!file) return;
    var img = new Image(), url = URL.createObjectURL(file);
    img.onload = function () {
      var max = 420, k = Math.min(1, max / Math.max(img.width, img.height));
      var cv = document.createElement('canvas'); cv.width = Math.round(img.width * k); cv.height = Math.round(img.height * k);
      cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height);
      state.identity.portrait = cv.toDataURL('image/jpeg', 0.85).split(',')[1];
      URL.revokeObjectURL(url); render();
    };
    img.onerror = function () { URL.revokeObjectURL(url); toast(tr('lab.err.portrait_file')); };
    img.src = url;
  }
  function portraitBox() {
    var p = state.identity.portrait;
    var fileInput = h('input', { type: 'file', accept: 'image/jpeg,image/png', class: 'sr-only', id: 'portrait-file', onchange: function (e) { loadPortrait(e.target.files[0]); } });
    return h('div', { class: 'lab-portrait' },
      p ? h('img', { class: 'lab-portrait-img', src: portraitSrc(p), alt: tr('lab.portrait'), width: '96', height: '120' }) : h('div', { class: 'lab-portrait-img empty' }, icon(ICONS.user), h('span', null, tr('lab.portrait.none'))),
      h('div', { class: 'lab-portrait-actions' }, h('strong', null, tr('lab.portrait')), fileInput,
        h('label', { for: 'portrait-file', class: 'btn btn-secondary btn-small', tabindex: '0', role: 'button', onkeydown: function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } } }, p ? tr('lab.portrait.replace') : tr('lab.portrait.add')),
        p ? h('button', { type: 'button', class: 'lab-link', onclick: function () { delete state.identity.portrait; render(); } }, tr('lab.portrait.remove')) : null));
  }
  function applyPreset(p) {
    state.identity = Object.assign({}, p.identity);
    state.creds = [];
    (p.credentials || []).forEach(function (c) { addCred(c.credentialConfigurationId, Object.assign({}, c.attributes || {}), false); });
    state.error = ''; render();
  }
  function presetsRow() {
    if (!state.presets.length) return null;
    return h('div', { class: 'lab-presets', role: 'group', 'aria-label': tr('lab.presets') }, state.presets.map(function (p) {
      var n = (p.credentials || []).length;
      return h('button', { type: 'button', class: 'lab-preset', onclick: function () { applyPreset(p); } },
        p.identity && p.identity.portrait ? h('img', { src: portraitSrc(p.identity.portrait), alt: '', width: '42', height: '42' }) : h('span', { class: 'lab-preset-ph' }),
        h('span', null, h('strong', null, p.name), h('small', null, '+ ' + tr(n === 1 ? 'lab.preset.one' : 'lab.preset.count', { n: String(n) }))));
    }));
  }

  function stepIdentity() {
    continueBtn = h('button', { type: 'button', class: 'btn', disabled: !identityReady(), onclick: function () { if (!identityReady()) return; if (!state.creds.length) addCred('eu.europa.ec.eudi.pid_mdoc', null, true); state.step = 2; state.error = ''; render(); } }, tr('lab.continue'), icon(ICONS.arrow));
    var prepared = state.creds.length ? h('div', { class: 'lab-prepared' }, h('strong', null, tr('lab.prepared', { n: String(state.creds.length) })), h('span', { class: 'muted' }, state.creds.map(function (c) { return nameOf(c.id); }).join(' · '))) : null;
    return [
      h('section', { class: 'panel lab-panel', 'aria-labelledby': 'lab-h1' },
        h('h2', { id: 'lab-h1' }, tr('lab.identity.title')), presetsRow(),
        h('div', { class: 'lab-identity' }, portraitBox(),
          h('div', { class: 'lab-fields' }, identityInput('given_name'), identityInput('family_name'), identityInput('birth_date', 'date'),
            h('p', { class: 'lab-optional' }, tr('lab.optional')), identityInput('nationality'), identityInput('resident_country')))),
      prepared,
      h('div', { class: 'lab-actions' }, h('span'), continueBtn)
    ];
  }

  function fieldInput(c, f) {
    var id = 'cf-' + c.uid + '-' + f.name, v = c.attrs[f.name];
    var set = function (val) { if (val === '' || val === undefined || val === null) delete c.attrs[f.name]; else c.attrs[f.name] = val; };
    var input;
    if (f.type === 'boolean') {
      input = h('select', { id: id, onchange: function (e) { set(e.target.value === '' ? '' : e.target.value === 'true'); } },
        h('option', { value: '' }, tr('lab.not_set')), h('option', { value: 'true', selected: v === true }, tr('lab.yes')), h('option', { value: 'false', selected: v === false }, tr('lab.no')));
    } else if (f.type === 'date') {
      input = h('input', { id: id, type: 'date', value: v || '', onchange: function (e) { set(e.target.value); } });
    } else if (f.type === 'number') {
      input = h('input', { id: id, type: 'number', inputmode: 'numeric', min: '0', placeholder: tr('lab.not_set'), value: v === undefined ? '' : String(v), oninput: function (e) { set(e.target.value === '' ? '' : Number(e.target.value)); } });
    } else {
      input = h('input', { id: id, type: 'text', autocomplete: 'off', placeholder: tr('lab.not_set'), value: v === undefined ? '' : String(v), oninput: function (e) { set(e.target.value); } });
    }
    return field(f.label, input, f.mandatory, id);
  }
  function credCard(c) {
    var conf = cfg(c.id), exp = c.expanded;
    var fields = conf ? conf.fields.filter(function (f) { return !SHARED[f.name] && f.valueType !== 'jpeg'; }) : [];
    var req = fields.filter(function (f) { return f.mandatory; }), opt = fields.filter(function (f) { return !f.mandatory; });
    var bodyId = 'cred-body-' + c.uid;
    var head = h('div', { class: 'lab-cred-head' },
      h('button', { type: 'button', class: 'lab-cred-toggle', 'aria-expanded': exp ? 'true' : 'false', 'aria-controls': bodyId, onclick: function () { c.expanded = !c.expanded; render(); } },
        h('span', { class: 'lab-cred-icon' }, icon(conf ? configIcon(conf) : ICONS.doc)), h('span', { class: 'lab-cred-name' }, nameOf(c.id)), h('span', { class: 'lab-cred-sum' }, exp ? '' : summary(c)), h('span', { class: 'lab-chevron' + (exp ? ' open' : '') }, icon(ICONS.chevron))),
      h('div', { class: 'lab-cred-tools' },
        h('button', { type: 'button', class: 'lab-icon-btn', title: tr('lab.duplicate'), 'aria-label': tr('lab.duplicate') + ': ' + nameOf(c.id), onclick: function () { state.creds.push({ uid: state.uid++, id: c.id, attrs: Object.assign({}, c.attrs), expanded: true }); render(); } }, icon(ICONS.copy)),
        h('button', { type: 'button', class: 'lab-icon-btn', title: tr('lab.delete'), 'aria-label': tr('lab.delete') + ': ' + nameOf(c.id), onclick: function () { state.creds = state.creds.filter(function (x) { return x !== c; }); render(); } }, icon(ICONS.trash))));
    var body = h('div', { class: 'lab-cred-body', id: bodyId, hidden: !exp }, h('div', { class: 'lab-fields' }, req.map(function (f) { return fieldInput(c, f); })),
      opt.length ? [h('p', { class: 'lab-optional' }, tr('lab.optional')), h('div', { class: 'lab-fields' }, opt.map(function (f) { return fieldInput(c, f); }))] : null);
    return h('li', { class: 'lab-cred' }, head, body);
  }

  function missing() {
    var out = [];
    state.creds.forEach(function (c) { var conf = cfg(c.id); if (!conf) return; conf.fields.forEach(function (f) { if (f.mandatory && !SHARED[f.name] && f.valueType !== 'jpeg' && (c.attrs[f.name] === undefined || c.attrs[f.name] === '')) out.push(nameOf(c.id) + ' – ' + f.label); }); });
    return out;
  }
  function createOffer() {
    if (state.busy) return;
    state.error = '';
    if (!state.creds.length) { state.error = tr('lab.no_credentials'); return render(); }
    var m = missing();
    if (m.length) { state.error = tr('lab.err.required', { fields: m.join(', ') }); return render(); }
    var needsPortrait = state.creds.some(function (c) { var conf = cfg(c.id); return conf && conf.fields.some(function (f) { return f.name === 'portrait' && f.mandatory; }); });
    if (needsPortrait && !state.identity.portrait) { state.error = tr('lab.err.portrait'); state.step = 1; return render(); }
    state.busy = true; render();
    var body = { identity: state.identity, credentials: state.creds.map(function (c) { var conf = cfg(c.id); var hasP = conf && conf.fields.some(function (f) { return f.name === 'portrait'; }); return Object.assign({ credentialConfigurationId: c.id, attributes: c.attrs }, hasP && state.identity.portrait ? { portraitFromIdentity: true } : {}); }) };
    api('/cases', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) }).then(function (res) { state.caseRec = res.case; state.step = 3; }).catch(function (e) { state.error = e.message; }).then(function () { state.busy = false; render(); });
  }
  function addDialog() {
    var dlg = h('dialog', { class: 'lab-dialog', 'aria-labelledby': 'add-h' },
      h('div', { class: 'lab-dialog-head' }, h('h2', { id: 'add-h' }, tr('lab.add.title')), h('button', { type: 'button', class: 'lab-icon-btn', 'aria-label': tr('lab.close'), onclick: function () { dlg.close(); } }, icon(ICONS.close))),
      h('ul', { class: 'lab-choose' }, state.configs.map(function (c) {
        return h('li', null, h('button', { type: 'button', class: 'lab-choice', onclick: function () { dlg.close(); addCred(c.id, null, true); render(); } }, h('span', { class: 'lab-cred-icon' }, icon(configIcon(c))), h('span', null, h('strong', null, c.name), h('small', null, c.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT VC'))));
      })));
    dlg.addEventListener('close', function () { dlg.remove(); });
    document.body.appendChild(dlg); dlg.showModal();
  }
  function personCard() {
    var p = state.identity.portrait;
    return h('aside', { class: 'panel lab-side' }, h('div', { class: 'lab-person' }, p ? h('img', { src: portraitSrc(p), alt: '', width: '64', height: '80', class: 'lab-person-img' }) : h('span', { class: 'lab-person-img empty' }, icon(ICONS.user)),
      h('div', null, h('strong', null, personName()), h('button', { type: 'button', class: 'lab-link', onclick: function () { state.step = 1; render(); } }, tr('lab.edit_identity')))),
      h('div', { class: 'lab-count' }, h('strong', null, String(state.creds.length)), h('span', null, tr('lab.prepared.short'))));
  }
  function stepCredentials() {
    return [
      h('div', { class: 'lab-two' },
        h('section', { class: 'panel lab-panel', 'aria-labelledby': 'lab-h2' },
          h('div', { class: 'lab-panel-head' }, h('h2', { id: 'lab-h2' }, tr('lab.creds.title')), h('button', { type: 'button', class: 'btn btn-secondary btn-small', onclick: addDialog }, icon(ICONS.plus), tr('lab.add_credential'))),
          state.creds.length ? h('ul', { class: 'lab-creds' }, state.creds.map(credCard)) : h('p', { class: 'note' }, tr('lab.no_credentials'))),
        personCard()),
      h('div', { class: 'lab-actions' },
        h('button', { type: 'button', class: 'btn btn-secondary', onclick: function () { state.step = 1; state.error = ''; render(); } }, icon(ICONS.back), tr('lab.back_identity')),
        h('button', { type: 'button', class: 'btn', disabled: state.busy, onclick: createOffer }, state.busy ? tr('lab.creating') : tr('lab.create_offer')))
    ];
  }

  function diagnostics() {
    var rec = state.caseRec; if (!rec) return;
    var tab = 'offer';
    var dlg = h('dialog', { class: 'lab-dialog wide', 'aria-labelledby': 'diag-h' });
    var content = h('div', { class: 'lab-diag' });
    function draw() {
      content.textContent = '';
      var tabs = h('div', { class: 'lab-tabs', role: 'tablist' },
        h('button', { type: 'button', role: 'tab', 'aria-selected': tab === 'offer' ? 'true' : 'false', class: tab === 'offer' ? 'active' : '', onclick: function () { tab = 'offer'; draw(); } }, tr('lab.tab.offer')),
        h('button', { type: 'button', role: 'tab', 'aria-selected': tab === 'sor' ? 'true' : 'false', class: tab === 'sor' ? 'active' : '', onclick: function () { tab = 'sor'; draw(); } }, tr('lab.tab.sor') + ' ' + rec.credentials.length));
      content.appendChild(tabs);
      if (tab === 'offer') {
        var row = function (label, value, copyIt) { return h('div', { class: 'lab-kv' }, h('span', { class: 'k' }, label), h('code', { class: 'v' }, value), copyIt ? h('button', { type: 'button', class: 'lab-link', onclick: function () { copy(value); } }, tr('lab.copy')) : null); };
        content.appendChild(row(tr('lab.subject'), rec.identifier, true));
        content.appendChild(row(tr('lab.sor_path'), '/sor/' + rec.identifier + '?credential-identifier=' + encodeURIComponent((rec.credentials[0] || {}).credentialIdentifier || '')));
        rec.credentials.forEach(function (c) { content.appendChild(row(tr('lab.cred_ids'), c.credentialConfigurationId + ' / ' + c.credentialIdentifier)); });
        if (rec.offer && rec.offer.uri) content.appendChild(row(tr('lab.deep_link'), rec.offer.uri, true));
        if (rec.offer && rec.offer.tx_code) content.appendChild(row(tr('lab.tx'), rec.offer.tx_code, true));
        if (rec.expiresAt) content.appendChild(h('p', { class: 'note' }, tr('lab.offer.expires', { time: new Date(rec.expiresAt).toLocaleString(LOCALE) })));
      } else {
        rec.credentials.forEach(function (c) {
          var a = Object.keys(c.attributes || {}).map(function (k) { var v = c.attributes[k]; return '  ' + JSON.stringify(k) + ': ' + (k === 'portrait' ? '"[JPEG base64]"' : JSON.stringify(v)); });
          content.appendChild(h('h3', null, nameOf(c.credentialConfigurationId) + ' · ' + c.credentialIdentifier));
          content.appendChild(h('pre', { class: 'lab-json', tabindex: '0' }, '{\n' + a.join(',\n') + '\n}'));
        });
      }
    }
    dlg.appendChild(h('div', { class: 'lab-dialog-head' }, h('h2', { id: 'diag-h' }, tr('lab.diagnostics')), h('button', { type: 'button', class: 'lab-icon-btn', 'aria-label': tr('lab.close'), onclick: function () { dlg.close(); } }, icon(ICONS.close))));
    dlg.appendChild(content); draw();
    dlg.addEventListener('close', function () { dlg.remove(); });
    document.body.appendChild(dlg); dlg.showModal();
  }
  function enlargeQr(src) {
    var dlg = h('dialog', { class: 'qr-dialog', 'aria-label': tr('lab.qr_alt') });
    dlg.appendChild(h('img', { class: 'qr-big', src: src, alt: tr('lab.qr_alt') }));
    dlg.appendChild(h('button', { type: 'button', class: 'btn btn-secondary', onclick: function () { dlg.close(); } }, tr('lab.close')));
    dlg.addEventListener('close', function () { dlg.remove(); });
    document.body.appendChild(dlg); dlg.showModal();
  }
  function regenerate() {
    if (state.busy || !state.caseRec) return;
    state.busy = true; state.error = ''; render();
    api('/cases/' + encodeURIComponent(state.caseRec.identifier) + '/offer', { method: 'POST' }).then(function (res) { state.caseRec = res.case; toast(tr('lab.regenerated')); }).catch(function (e) { state.error = e.message; }).then(function () { state.busy = false; render(); });
  }
  function stepOffer() {
    var rec = state.caseRec, offer = rec && rec.offer;
    if (!offer || !offer.uri) return [errorBox() || h('div', { class: 'alert alert-error', role: 'alert' }, (rec && rec.offerError) || tr('lab.err.generic')), h('div', { class: 'lab-actions' }, h('button', { type: 'button', class: 'btn btn-secondary', onclick: function () { state.step = 2; render(); } }, icon(ICONS.back), tr('lab.edit')), h('button', { type: 'button', class: 'btn', onclick: regenerate }, tr('lab.regenerate')))];
    return [
      h('section', { class: 'panel lab-panel lab-offer', 'aria-labelledby': 'lab-h3' },
        h('h2', { id: 'lab-h3' }, tr('lab.offer.title')),
        h('div', { class: 'lab-offer-grid' },
          h('div', null,
            offer.tx_code ? h('div', { class: 'lab-tx' }, h('div', null, h('small', null, tr('lab.tx')), h('strong', { class: 'lab-tx-code' }, offer.tx_code)), h('button', { type: 'button', class: 'btn btn-secondary btn-small', onclick: function () { copy(offer.tx_code); } }, tr('lab.copy_code'))) : null,
            h('a', { class: 'btn btn-large lab-open', href: offer.uri }, tr('lab.open_wallet'), icon(ICONS.arrow)),
            h('p', null, h('button', { type: 'button', class: 'lab-link', onclick: function () { copy(offer.uri); } }, tr('lab.copy_link'))),
            rec.expiresAt ? h('p', { class: 'note' }, tr('lab.offer.expires', { time: new Date(rec.expiresAt).toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit' }) })) : null),
          offer.qr_code ? h('div', { class: 'lab-qr' }, h('img', { class: 'qr lab-qr-img', src: 'data:image/png;base64,' + offer.qr_code, width: '340', height: '340', alt: tr('lab.qr_alt') }), h('p', { class: 'note' }, tr('lab.offer.scan')), h('button', { type: 'button', class: 'btn btn-secondary btn-small', onclick: function () { enlargeQr('data:image/png;base64,' + offer.qr_code); } }, tr('lab.qr.enlarge'))) : null)),
      h('details', { class: 'panel lab-person-sum' }, h('summary', null, state.identity.portrait ? h('img', { src: portraitSrc(state.identity.portrait), alt: '', width: '40', height: '50', class: 'lab-person-img' }) : null, h('span', null, h('strong', null, personName()), h('small', null, tr('lab.prepared', { n: String(rec.credentials.length) })))),
        h('ul', { class: 'plain' }, rec.credentials.map(function (c) { return h('li', null, nameOf(c.credentialConfigurationId)); }))),
      h('div', { class: 'lab-actions' },
        h('button', { type: 'button', class: 'btn btn-secondary', onclick: function () { state.step = 2; state.error = ''; render(); } }, icon(ICONS.back), tr('lab.edit')),
        h('span', { class: 'lab-action-group' }, h('button', { type: 'button', class: 'btn btn-secondary', onclick: diagnostics }, tr('lab.diagnostics')), h('button', { type: 'button', class: 'btn btn-secondary', disabled: state.busy, onclick: regenerate }, tr('lab.regenerate'))))
    ];
  }

  function render() {
    var focusId = document.activeElement && document.activeElement.id;
    root.textContent = '';
    if (state.loading) { root.appendChild(h('p', { class: 'note', role: 'status' }, tr('lab.loading'))); return; }
    if (state.loadError) { root.appendChild(h('div', { class: 'alert alert-error', role: 'alert' }, tr('lab.load_error'))); root.appendChild(h('button', { type: 'button', class: 'btn', onclick: load }, tr('lab.retry'))); return; }
    root.appendChild(steps());
    var eb = errorBox(); if (eb) root.appendChild(eb);
    [].concat(state.step === 1 ? stepIdentity() : state.step === 2 ? stepCredentials() : stepOffer()).forEach(function (n) { if (n) root.appendChild(n); });
    if (focusId) { var el = document.getElementById(focusId); if (el && el.focus) el.focus(); }
  }
  function load() {
    state.loading = true; state.loadError = false; render();
    Promise.all([api('/presets'), api('/configurations?locale=' + encodeURIComponent(LOCALE))]).then(function (r) { state.presets = r[0].presets || []; state.configs = r[1].configurations || []; state.loading = false; render(); })
      .catch(function (e) { console.error("lab load", e); state.loading = false; state.loadError = true; render(); });
  }
  load();
})();
