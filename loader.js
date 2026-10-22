/* Generic loader for an encrypted personal app. It holds no data and no app logic of its own:
   it downloads the encrypted file from this site (or opens one you pick from iCloud Drive), decrypts it
   with your password, and runs what's inside. Nothing is sent anywhere (see the Content-Security-Policy in index.html).
   File: "MTP1" | salt (16) | iv (12) | AES-256-GCM ciphertext+tag; key = PBKDF2-SHA256(password, salt, 600,000). */
(function () {
  'use strict';
  const MAGIC = 'MTP1', ITER = 600000;
  const $ = id => document.getElementById(id);
  const b64 = u8 => btoa(String.fromCharCode.apply(null, u8));

  // ---------- tiny IndexedDB key-value store ----------
  let dbp = null;
  const db = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open('money-phone', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  }));
  const kv = {
    async get(k) { const d = await db(); return new Promise((res, rej) => { const r = d.transaction('kv').objectStore('kv').get(k); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); },
    async set(k, v) { const d = await db(); return new Promise((res, rej) => { const t = d.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = () => res(); t.onerror = () => rej(t.error); }); },
    async del(k) { const d = await db(); return new Promise((res, rej) => { const t = d.transaction('kv', 'readwrite'); t.objectStore('kv').delete(k); t.oncomplete = () => res(); t.onerror = () => rej(t.error); }); },
  };
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});

  // ---------- crypto ----------
  function parse(buf) {
    const u8 = new Uint8Array(buf);
    if (u8.length < 60 || String.fromCharCode(u8[0], u8[1], u8[2], u8[3]) !== MAGIC) throw new Error("That's not the Money file. Pick money.mtp from iCloud Drive → Money Phone.");
    return { salt: u8.slice(4, 20), iv: u8.slice(20, 32), body: u8.slice(32) };
  }
  async function deriveKey(password, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function open(buf, key) {
    const p = parse(buf);
    let plain;
    try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.iv }, key, p.body); }
    catch (e) { throw new Error('Wrong password.'); }
    const data = JSON.parse(new TextDecoder().decode(plain));
    if (!data || data.kind !== 'snapshot' || !data.code || !data.docs) throw new Error('This file is damaged.');
    return data;
  }
  async function seal(obj, key, salt) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const body = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
    const out = new Uint8Array(32 + body.length);
    out.set(new TextEncoder().encode(MAGIC), 0); out.set(salt, 4); out.set(iv, 20); out.set(body, 32);
    return out;
  }

  // ---------- picking a file (needs a tap) ----------
  function pickFile() {
    return new Promise(resolve => {
      const inp = document.createElement('input');
      inp.type = 'file';
      inp.accept = '.mtp,application/octet-stream';
      let done = false;
      const finish = f => { if (!done) { done = true; resolve(f); } };
      inp.addEventListener('change', () => finish(inp.files && inp.files[0] ? inp.files[0] : null));
      inp.addEventListener('cancel', () => finish(null));
      // Some iOS versions send no "cancel"; treat coming back without a file as cancel.
      window.addEventListener('focus', () => setTimeout(() => finish(inp.files && inp.files[0] ? inp.files[0] : null), 1500), { once: true });
      inp.click();
    });
  }

  // ---------- downloading the newest file from this site ----------
  // Returns the file's bytes, or null when offline / not there.
  async function download() {
    try {
      const r = await fetch('money.mtp?t=' + Date.now(), { cache: 'no-store' });
      if (!r.ok) return null;
      const buf = await r.arrayBuffer();
      parse(buf);
      return buf;
    } catch (e) { return null; }
  }
  // Swaps in the downloaded file when it's newer than what's shown. Returns 'new', 'same' or null (offline).
  async function checkOnline() {
    if (!ctx) return null;
    const buf = await download();
    if (!buf) return null;
    if (b64(parse(buf).salt) !== b64(ctx.salt)) throw new Error('The Mac uses a different password now. Tap Lock, then open it again.');
    const next = await open(buf, ctx.key);
    if (!(next.at > ctx.data.at)) return 'same';
    await kv.set('snap', buf);
    await prunePending(next.docs);
    location.reload();
    return 'new';
  }

  // ---------- gate screens ----------
  let fileBuf = null;
  function show(step, message) {
    $('root').innerHTML = '';
    $('gate').classList.remove('hidden');
    $('step-file').classList.toggle('hidden', step !== 'file');
    $('step-pass').classList.toggle('hidden', step !== 'pass');
    $('msg').textContent = message || '';
    $('msg').classList.toggle('hidden', !message);
    if (step === 'pass') setTimeout(() => $('pw').focus(), 50);
  }
  $('pick').onclick = async () => {
    const f = await pickFile();
    if (!f) return;
    try { fileBuf = await f.arrayBuffer(); parse(fileBuf); show('pass'); }
    catch (e) { show('file', e.message); }
  };
  $('other').onclick = () => { fileBuf = null; show('file'); };
  const doUnlock = async () => {
    const pw = $('pw').value;
    if (!pw) return;
    $('unlock').disabled = true; $('unlock').textContent = 'Unlocking…';
    try {
      const buf = fileBuf || await kv.get('snap');
      const p = parse(buf);
      const key = await deriveKey(pw, p.salt);
      const data = await open(buf, key);
      await kv.set('snap', buf); await kv.set('key', key); await kv.set('salt', b64(p.salt));
      $('pw').value = ''; fileBuf = null;
      await prunePending(data.docs);
      run(data, key, p.salt);
    } catch (e) { show('pass', e.message); }
    finally { $('unlock').disabled = false; $('unlock').textContent = 'Unlock'; }
  };
  $('unlock').onclick = doUnlock;
  $('pw').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });

  // ---------- purchases added on the phone ----------
  // pending: { id: txn } — shown in the app right away, sent to the Mac as an encrypted .mtq file.
  let pending = {}, readyFile = null, ctx = null;
  const idsIn = docs => { const s = new Set(); Object.keys(docs).forEach(k => { if (k.startsWith('m_')) (docs[k].txns || []).forEach(t => s.add(t.id)); }); return s; };
  async function prunePending(docs) {
    const p = (await kv.get('pending')) || {};
    const have = idsIn(docs);
    Object.keys(p).forEach(id => { if (have.has(id)) delete p[id]; });
    await kv.set('pending', p);
    if (!Object.keys(p).length) await kv.del('sentAt');
  }
  async function refreshReadyFile() {
    const list = Object.values(pending);
    if (!list.length || !ctx) { readyFile = null; return; }
    const bytes = await seal({ kind: 'phone-adds', v: 1, at: new Date().toISOString(), txns: list }, ctx.key, ctx.salt);
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
    readyFile = new File([bytes], 'money-phone-adds-' + stamp + '.mtq', { type: 'application/octet-stream' });
  }

  // ---------- running the app from the file ----------
  function loadScript(text) {
    return new Promise((res, rej) => {
      const url = URL.createObjectURL(new Blob([text], { type: 'text/javascript' }));
      const s = document.createElement('script');
      s.src = url; s.onload = () => { URL.revokeObjectURL(url); res(); }; s.onerror = () => rej(new Error('Could not start the app.'));
      document.body.appendChild(s);
    });
  }
  async function run(data, key, salt) {
    ctx = { data, key, salt };
    pending = (await kv.get('pending')) || {};
    await refreshReadyFile();
    $('gate').classList.add('hidden');
    const style = document.createElement('style');
    style.textContent = data.code.css;
    document.head.appendChild(style);
    const base = data.docs;
    const merged = () => {
      const docs = JSON.parse(JSON.stringify(base));
      Object.values(pending).forEach(t => {
        const k = 'm_' + t.date.slice(0, 7);
        const m = docs[k] || (docs[k] = { bal: {}, fx: {}, totals: {}, notes: '', txns: [] });
        m.txns = m.txns || [];
        if (!m.txns.some(x => x.id === t.id)) m.txns.push(t);
      });
      return docs;
    };
    window.MT_PHONE = {
      isPending: id => !!pending[id],
      info: () => ({ at: data.at, pending: Object.keys(pending).length, sentAt: ctx.sentAt || null }),
      async update() {
        const r = await checkOnline();
        if (r === 'same') return 'Already up to date.';
        if (r === 'new') return 'Updated.';
        const f = await pickFile(); // offline: pick the file from iCloud Drive instead
        if (!f) return '';
        const buf = await f.arrayBuffer();
        const p = parse(buf);
        if (b64(p.salt) !== b64(ctx.salt)) throw new Error('This file uses a different password. Tap Lock, then open it again.');
        const next = await open(buf, ctx.key);
        await kv.set('snap', buf);
        await prunePending(next.docs);
        location.reload();
        return 'Updated.';
      },
      send() {
        if (!readyFile) return Promise.resolve('Nothing to send.');
        const note = () => { ctx.sentAt = new Date().toISOString(); kv.set('sentAt', ctx.sentAt); };
        // share() must run straight from the tap, so the file is prepared in advance.
        if (navigator.canShare && navigator.canShare({ files: [readyFile] })) {
          return navigator.share({ files: [readyFile], title: 'Money: purchases from iPhone' })
            .then(() => { note(); return 'Sent. Choose Money Inbox if you haven\'t. The Mac adds them when it\'s on.'; })
            .catch(e => (e && e.name === 'AbortError' ? '' : 'Could not open the share sheet.'));
        }
        const a = document.createElement('a');
        a.href = URL.createObjectURL(readyFile); a.download = readyFile.name; a.click();
        note();
        return Promise.resolve('Saved. Move it to iCloud Drive → Money Inbox.');
      },
      async lock() { await kv.del('key'); location.reload(); },
    };
    window.MT_OPEN_STORE = async () => ({
      kind: 'phone',
      async loadAll() { return merged(); },
      async put(key, value) {
        if (!/^m_\d{4}-\d{2}$/.test(key) || !value) return; // the phone only adds purchases
        const month = key.slice(2);
        const baseIds = new Set(((base[key] || {}).txns || []).map(t => t.id));
        Object.keys(pending).forEach(id => { if (pending[id].date.slice(0, 7) === month) delete pending[id]; });
        (value.txns || []).forEach(t => { if (!baseIds.has(t.id)) pending[t.id] = t; });
        await kv.set('pending', pending);
        await refreshReadyFile();
      },
      async del() {},
      subscribe() { return () => {}; },
      async sync() {}, async backup() {},
    });
    ctx.sentAt = await kv.get('sentAt');
    await loadScript(data.code.logic);
    await loadScript(data.code.app);
    checkOnline().catch(() => {});
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') checkOnline().catch(() => {}); });
  }

  // ---------- start ----------
  (async () => {
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
    try {
      const snap = await kv.get('snap');
      if (!snap) {
        fileBuf = await download();
        return show(fileBuf ? 'pass' : 'file');
      }
      const key = await kv.get('key');
      if (!key) return show('pass');
      const data = await open(snap, key);
      const p = parse(snap);
      run(data, key, p.salt);
    } catch (e) { show('pass', e.message); }
  })();
})();
