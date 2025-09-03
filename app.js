// ================== Stałe i ustawienia ==================
const META_KEY = 'vault_meta_v1';
const BLOB_KEY = 'vault_blob_v1';
const SETTINGS_KEY = 'vault_settings_v1';
const THEME_KEY = 'vault_theme';

// Szybkie odblokowanie (FaceID/TouchID)
const QUICK_BLOB_KEY = 'vault_quick_blob_v1';      // zaszyfrowana kopia sejfu kluczem z passkey
const PASSKEY_ID_KEY = 'vault_passkey_id_v1';      // id poświadczenia (rawId b64url)
const PASSKEY_USER_ID_KEY = 'vault_passkey_userid_v1'; // user.id (b64url) – czysto lokalnie
const PASSKEY_SALT = new TextEncoder().encode('vault-quick-v1'); // sól do PRF/HKDF

const DEFAULT_ITER = 300_000;

let settings = {
  autolockMin: 5,
  ageDays: 180,
  maskEnabled: true,
  protectPwChange: true,   // potwierdzenie przed zmianą
  historySize: 3,          // ile haseł trzymać w historii
  filters: { old: true, short: true, weak: true, dup: true }
};
let autolockMinutes = settings.autolockMin;

// ================== Pomocnicze ==================
const $ = s => document.querySelector(s);
const enc = new TextEncoder(); const dec = new TextDecoder();

const b64 = buf => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin=''; for(let i=0;i<bytes.length;i++) bin+=String.fromCharCode(bytes[i]); return btoa(bin);
};
const fromB64 = str => { const bin=atob(str); const out=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; };

const b64url = buf => b64(buf).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const fromB64url = s => fromB64(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'='));

const nowIso = () => new Date().toISOString();
const daysBetween = iso => Math.floor((Date.now() - new Date(iso).getTime()) / (1000*60*60*24));
function escapeHtml(str){ return String(str??'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function escapeRegExp(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function highlight(text,q){ const safe=escapeHtml(text||''); if(!q) return safe; const re=new RegExp(`(${escapeRegExp(q)})`,'ig'); return safe.replace(re,'<mark>$1</mark>'); }
function colorFromString(s){ const str=String(s||''); let h=0; for(let i=0;i<str.length;i++) h=(h*31+str.charCodeAt(i))>>>0; return `hsl(${h%360} 70% 50%)`; }
const systemPrefersDark = () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

// ================== Kryptografia ==================
async function deriveKey(password, saltB64, iterations){
  const salt = fromB64(saltB64);
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations, hash:'SHA-256' },
    keyMaterial, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}
async function encryptJson(obj, key){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, data);
  return { iv: b64(iv), ciphertext: b64(ct) };
}
async function decryptJson(payload, key){
  const iv = fromB64(payload.iv); const ct = fromB64(payload.ciphertext);
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return JSON.parse(dec.decode(pt));
}

// HKDF z tajemnicy PRF -> klucz AES
async function prfToAesKey(secretAB){
  const material = await crypto.subtle.importKey('raw', secretAB, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt: enc.encode('vault-hkdf-salt'), info: PASSKEY_SALT },
    material,
    { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}

// ================== Stan sejfu ==================
let masterKey = null;    // klucz z hasła
let quickKey = null;     // klucz z passkey (biometrii)
let vault = null;        // { entries:[...] }
let meta = null;         // { salt, iterations, version }
let unlocking = false;   // anty-dubel

// ================== Autoblokada ==================
let lastActivity = Date.now();
const bumpActivity = () => { lastActivity = Date.now(); };
['click','keydown','mousemove','scroll','touchstart'].forEach(ev => document.addEventListener(ev, bumpActivity, { passive:true }));
setInterval(() => {
  if (!masterKey && !quickKey) return;
  const minutes = (Date.now() - lastActivity) / 60000;
  if (minutes >= autolockMinutes) { lockApp(); alert('Auto-blokada po bezczynności.'); }
}, 10_000);

// ================== Elementy UI ==================
const lockView = $('#lockView'), vaultView = $('#vaultView'), generatorView = $('#generatorView'),
      auditView = $('#auditView'), backupView = $('#backupView'), settingsView = $('#settingsView');

const lockTitle = $('#lockTitle'), lockInfo = $('#lockInfo'),
      masterInput = $('#masterInput'), masterConfirm = $('#masterConfirm'),
      confirmLabel = $('#confirmLabel'), unlockBtn = $('#unlockBtn'),
      bioUnlockBtn = $('#bioUnlock'), bioHint = $('#bioHint');

const listEl = $('#list'), searchEl = $('#search'), emptyInfo = $('#emptyInfo'),
      addEntryBtn = $('#addEntryBtn'), lockBtn = $('#lockBtn'), filtersBar = $('#filtersBar');

const genLen = $('#genLen'), genLower = $('#genLower'), genUpper = $('#genUpper'),
      genDigits = $('#genDigits'), genSymbols = $('#genSymbols'),
      genBtn = $('#genBtn'), genOut = $('#genOut'),
      genCopy = $('#genCopy'), genCopied = $('#genCopied'),
      genMeterBar = $('#genMeterBar'), genMeterLabel = $('#genMeterLabel');

const runAuditBtn = $('#runAuditBtn'), auditResults = $('#auditResults');

const exportBtn = $('#exportBtn'), importFile = $('#importFile'),
      chooseFileBtn = $('#chooseFileBtn'), fileNameEl = $('#fileName'),
      importBtn = $('#importBtn');

const themeToggle = $('#themeToggle');

// Ustawienia
const setAutolock = $('#setAutolock'), setAgeDays = $('#setAgeDays'),
      fOld = $('#fOld'), fShort = $('#fShort'), fWeak = $('#fWeak'), fDup = $('#fDup'),
      saveSettingsBtn = $('#saveSettings'), savedInfo = $('#savedInfo');
const setMask = $('#setMask');
const passkeySetupBtn = $('#passkeySetup'), passkeyRemoveBtn = $('#passkeyRemove'), passkeyState = $('#passkeyState');

const privacyMask = $('#privacyMask');

// ================== Widoki / Zakładki ==================
const views = { vault: vaultView, generator: generatorView, audit: auditView, backup: backupView, settings: settingsView };
const getTabButtons = () => document.querySelectorAll('#tabs [data-tab], #menuPanel [data-tab]');

function showTab(name){
  Object.values(views).forEach(v => { v.classList.remove('active'); v.style.display='none'; });
  if (views[name]) { views[name].classList.add('active'); views[name].style.display='block'; }
  getTabButtons().forEach(b => b.classList.toggle('active', b.dataset.tab === name));
}

// --- hamburger (mobile) ---
const menuBtn      = document.getElementById('menuBtn');
const menuPanel    = document.getElementById('menuPanel');
const menuBackdrop = document.getElementById('menuBackdrop');
const menuClose    = document.getElementById('menuClose');

function openMenu(){ if(!menuPanel) return; menuPanel.hidden=false; requestAnimationFrame(()=> menuPanel.classList.add('open')); menuBtn?.setAttribute('aria-expanded','true'); }
function closeMenu(){ if(!menuPanel) return; menuPanel.classList.remove('open'); setTimeout(()=> menuPanel.hidden=true,180); menuBtn?.setAttribute('aria-expanded','false'); }
menuBtn?.addEventListener('click', ()=> menuPanel.hidden ? openMenu() : closeMenu());
menuBackdrop?.addEventListener('click', closeMenu);
menuClose?.addEventListener('click', closeMenu);
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !menuPanel.hidden) closeMenu(); });
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-tab]'); if (!btn) return;
  showTab(btn.dataset.tab);
  if (btn.closest('.menu-sheet')) closeMenu();
  const barBtn = document.querySelector(`.tabs .bar [data-tab="${btn.dataset.tab}"]`);
  barBtn?.scrollIntoView({ behavior:'smooth', inline:'center', block:'nearest' });
});

// ================== Motyw ==================
function applyTheme(theme){
  const t = theme || localStorage.getItem(THEME_KEY) || (systemPrefersDark() ? 'dark' : 'light');
  document.documentElement.classList.toggle('theme-dark', t === 'dark');
  localStorage.setItem(THEME_KEY, t);
  if (themeToggle) themeToggle.textContent = t === 'dark' ? '☀️' : '🌙';
  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if (metaTheme) metaTheme.setAttribute('content', t === 'dark' ? '#0f1116' : '#f6f7fb');
}
themeToggle?.addEventListener('click', ()=> applyTheme(document.documentElement.classList.contains('theme-dark') ? 'light' : 'dark'));
if (window.matchMedia){
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!localStorage.getItem(THEME_KEY)) applyTheme(e.matches ? 'dark' : 'light');
  });
}

// ================== Ustawienia – load/save ==================
function loadSettings(){
  try{
    const s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || 'null');
    if (s){ settings = { ...settings, ...s, filters: { ...settings.filters, ...(s.filters||{}) } }; }
  }catch{}
  autolockMinutes = Number(settings.autolockMin) || 5;
  setAutolock && (setAutolock.value = String(settings.autolockMin));
  setAgeDays && (setAgeDays.value = String(settings.ageDays));
  fOld && (fOld.checked = !!settings.filters.old);
  fShort && (fShort.checked = !!settings.filters.short);
  fWeak && (fWeak.checked = !!settings.filters.weak);
  fDup && (fDup.checked = !!settings.filters.dup);
  setMask && (setMask.checked = !!settings.maskEnabled);
  rebuildFiltersBar();
  updatePasskeyState();
}
function saveSettings(){
  settings.autolockMin = Number(setAutolock.value || 5);
  settings.ageDays = Math.max(1, Math.min(3650, Number(setAgeDays.value || 180)));
  settings.filters = { old: fOld.checked, short: fShort.checked, weak: fWeak.checked, dup: fDup.checked };
  settings.maskEnabled = !!setMask.checked;
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
  autolockMinutes = settings.autolockMin;
  rebuildFiltersBar();
  savedInfo.hidden = false; setTimeout(()=> savedInfo.hidden = true, 1200);
}
saveSettingsBtn?.addEventListener('click', saveSettings);

// ================== Start / Setup / Lock ==================
function checkSetup(){
  meta = JSON.parse(localStorage.getItem(META_KEY) || 'null');
  const hasVault = !!localStorage.getItem(BLOB_KEY);
  if (!meta || !hasVault){
    meta = { version:1, iterations:DEFAULT_ITER, salt:b64(crypto.getRandomValues(new Uint8Array(16))) };
    localStorage.setItem(META_KEY, JSON.stringify(meta));
    showLock(true);
  } else { showLock(false); }
  updateBioUI();
}
function showLock(isSetup){
hideMask();
  document.body.classList.add('locked'); document.body.classList.remove('unlocked');
  lockView.style.display='block'; showTab('vault');
  confirmLabel.hidden = !isSetup;
  lockTitle.textContent = isSetup ? 'Ustaw hasło główne' : 'Odblokuj sejf';
  lockInfo.textContent = isSetup ? `Ustawiasz hasło główne. Iteracje PBKDF2: ${meta.iterations}.`
                                 : `Podaj hasło główne, aby odszyfrować sejf.`;
  masterInput.value=''; masterConfirm.value=''; masterInput.focus();
  [vaultView,generatorView,auditView,backupView,settingsView].forEach(v => v.style.display='none');
  updateBioUI();
}
function showMain(){
  document.body.classList.remove('locked'); document.body.classList.add('unlocked');
  lockView.style.display='none'; showTab('vault'); renderList(); searchEl.value='';
  bumpActivity(); hideMask();
}
function lockApp(){ masterKey=null; quickKey=null; showLock(false); }

async function handleUnlock(){
  if (unlocking) return; unlocking = true;
  try{
    const pwd = masterInput.value; const isSetup = confirmLabel.hidden === false;
    if (!pwd){ alert('Wpisz hasło.'); return; }

    if (isSetup){
      if (pwd.length < 8){ alert('Hasło główne powinno mieć co najmniej 8 znaków.'); return; }
      if (pwd !== masterConfirm.value){ alert('Hasła nie są takie same.'); return; }
      masterKey = await deriveKey(pwd, meta.salt, meta.iterations);
      vault = { entries: [], createdAt: nowIso(), updatedAt: nowIso() };
      await persistVault();
      showMain();
    } else {
      try{
        masterKey = await deriveKey(pwd, meta.salt, meta.iterations);
        const payload = JSON.parse(localStorage.getItem(BLOB_KEY));
        vault = await decryptJson(payload, masterKey);
        showMain();
      }catch(e){ masterKey=null; vault=null; alert('Niepoprawne hasło (nie udało się odszyfrować).'); }
    }
  } finally { unlocking=false; }
}
unlockBtn.onclick = handleUnlock;
masterInput.onkeydown = e => { if (e.key==='Enter'){ e.preventDefault(); handleUnlock(); } };
masterConfirm.onkeydown = e => { if (e.key==='Enter'){ e.preventDefault(); handleUnlock(); } };

// ================== Persist ==================
async function persistVault(){
  if (!vault) return;
  vault.updatedAt = nowIso();
  if (masterKey){
    const payload = await encryptJson(vault, masterKey);
    localStorage.setItem(BLOB_KEY, JSON.stringify(payload));
    localStorage.setItem(META_KEY, JSON.stringify(meta));
  }
  if (quickKey && localStorage.getItem(PASSKEY_ID_KEY)){
    const payloadQ = await encryptJson(vault, quickKey);
    localStorage.setItem(QUICK_BLOB_KEY, JSON.stringify(payloadQ));
  }
}

// ================== Filtry – UI ==================
let activeFilter = 'all';
function rebuildFiltersBar(){
  if (!filtersBar) return;
  const items = [{key:'all', label:'Wszystkie'}];
  if (settings.filters.old)   items.push({key:'old',   label:'Stare'});
  if (settings.filters.short) items.push({key:'short', label:'Krótkie'});
  if (settings.filters.weak)  items.push({key:'weak',  label:'Słabe'});
  if (settings.filters.dup)   items.push({key:'dup',   label:'Powtórzone'});

  filtersBar.innerHTML = items.map(i => `<button class="chip ${activeFilter===i.key?'active':''}" data-filter="${i.key}">${i.label}</button>`).join('');
  filtersBar.querySelectorAll('button').forEach(btn => btn.addEventListener('click', () => {
    activeFilter = btn.dataset.filter; rebuildFiltersBar(); if (vault) renderList();
  }));
}

// ================== Lista / wpisy ==================
function ensureUnlocked(){ if(!masterKey && !quickKey){ alert('Sejf jest zablokowany.'); throw new Error('locked'); } }

function entryContext(id){
  const e = vault.entries.find(x => x.id === id) || {};
  const parts = []; if (e.title) parts.push(e.title); if (e.username) parts.push(e.username);
  if (e.url){ try{ parts.push(new URL(e.url).hostname); }catch{} } return parts;
}

function filteredEntries(){
  const q = (searchEl.value||'').trim().toLowerCase();
  let arr = vault.entries.slice();
  if (activeFilter !== 'all'){
    if (activeFilter === 'old'){
      arr = arr.filter(e => { const when = e.pwChangedAt || e.updatedAt || e.createdAt || nowIso(); return daysBetween(when) > (settings.ageDays||180); });
    } else if (activeFilter === 'short'){
      arr = arr.filter(e => (e.password||'').length && e.password.length < 12);
    } else if (activeFilter === 'weak'){
      arr = arr.filter(e => { const m = measureStrength(e.password||'', entryContext(e.id)); return (e.password||'').length && m.score <= 1; });
    } else if (activeFilter === 'dup'){
      const map = new Map(); for (const e of arr){ const p=e.password||''; if (!p) continue; if (!map.has(p)) map.set(p,[]); map.get(p).push(e); }
      const dupIds = new Set(); for (const [p,list] of map.entries()){ if (p && list.length>=2) list.forEach(x => dupIds.add(x.id)); }
      arr = arr.filter(e => dupIds.has(e.id));
    }
  }
  if (!q) return arr;
  return arr.filter(e =>
    (e.title||'').toLowerCase().includes(q) ||
    (e.username||'').toLowerCase().includes(q) ||
    (e.url||'').toLowerCase().includes(q)
  );
}

function renderList(){
  ensureUnlocked();
  const entries = filteredEntries();
  listEl.innerHTML = ''; emptyInfo.hidden = entries.length !== 0;

  for (const e of entries){
    const card = document.createElement('div'); card.className='entry';
    let host=''; try{ host = e.url ? new URL(e.url).hostname : ''; }catch{}
    const stripe = colorFromString(host || e.title || e.username || '');
    card.style.setProperty('--stripe', stripe); card.style.setProperty('--accent', stripe);

    const q = (searchEl.value||'').trim();
    const when = e.pwChangedAt || e.updatedAt || e.createdAt || nowIso();
    const days = daysBetween(when);
    const ageBadge = `<span class="badge ${days>(settings.ageDays||180)?'bad':'muted'}">hasło: ${days} dni</span>`;

    card.innerHTML = `
      <div class="entry-header">
        <div class="entry-title">${highlight(e.title || '(bez tytułu)', q)}</div>
        <div class="badges">
          ${e.url ? `<span class="badge"><a href="${escapeHtml(e.url)}" target="_blank" rel="noopener">Otwórz</a></span>` : ''}
          ${ageBadge}
          <span class="badge muted">zmieniono: ${new Date(e.updatedAt).toLocaleString()}</span>
        </div>
      </div>
      <div class="grid">
        <label>Tytuł
          <input type="text" data-id="${e.id}" data-field="title" value="${escapeHtml(e.title)}" />
        </label>
        <label>Login / e-mail
          <input type="text" data-id="${e.id}" data-field="username" value="${escapeHtml(e.username)}" />
        </label>
        <label>Hasło
          <div class="row">
            <input type="password" data-id="${e.id}" data-field="password" value="${escapeHtml(e.password)}" class="grow" />
            <button class="secondary reveal" data-id="${e.id}">Pokaż</button>
            <button class="secondary copy" data-id="${e.id}">Kopiuj</button>
            <span class="copy-ok" id="copied-${e.id}" hidden>Skopiowano ✓</span>
          </div>
          <div class="meter">
            <div class="bar"><span id="bar-${e.id}"></span></div>
            <div class="label" id="label-${e.id}"></div>
          </div>
        </label>
        <label>Adres (URL)
          <input type="url" placeholder="https://…" data-id="${e.id}" data-field="url" value="${escapeHtml(e.url)}" />
        </label>
        <label class="full">Notatki
          <textarea data-id="${e.id}" data-field="notes">${escapeHtml(e.notes)}</textarea>
        </label>
      </div>
${renderHistory(e)}
      <div class="row">
        <button class="ghost genFor" data-id="${e.id}">Wygeneruj hasło dla tego wpisu</button>
        <span style="margin-left:auto"></span>
        <button class="danger del" data-id="${e.id}">Usuń</button>
      </div>
    `;
    listEl.appendChild(card);
  }

  // inputy + live meter
  listEl.querySelectorAll('input, textarea').forEach(el => {
    const field = el.getAttribute('data-field'); const id = el.getAttribute('data-id'); if (!field || !id) return;
    el.addEventListener('change', ev => {
  const entry = vault.entries.find(x => x.id===id);
  if (field === 'password'){
    if (entry && entry.password !== ev.target.value){
      changePassword(id, ev.target.value);
    }
  } else {
    updateEntry(id, { [field]: ev.target.value });
    renderList();
  }
});
    if (field === 'password'){
      el.addEventListener('input', ev => { const m = measureStrength(ev.target.value, entryContext(id)); updateMeter(`bar-${id}`, `label-${id}`, m); });
      const m = measureStrength(el.value, entryContext(id)); updateMeter(`bar-${id}`, `label-${id}`, m);
    }
  });

  // akcje
  listEl.querySelectorAll('button.reveal').forEach(btn => btn.addEventListener('click', () => {
    const id = btn.getAttribute('data-id'); const input = listEl.querySelector(`input[data-id="${id}"][data-field="password"]`);
    if (input.type === 'password'){ input.type='text'; btn.textContent='Ukryj'; } else { input.type='password'; btn.textContent='Pokaż'; }
  }));
  listEl.querySelectorAll('button.copy').forEach(btn => btn.addEventListener('click', async () => {
    const id = btn.getAttribute('data-id'); const input = listEl.querySelector(`input[data-id="${id}"][data-field="password"]`);
    try{ await navigator.clipboard.writeText(input.value||''); const ok=$(`#copied-${id}`); ok.hidden=false; setTimeout(()=> ok.hidden=true,1500); } catch{ alert('Nie udało się skopiować.'); }
  }));
  listEl.querySelectorAll('button.genFor').forEach(btn => {
  btn.addEventListener('click', () => {
    const id = btn.getAttribute('data-id');
    const pass = generatePassword();
    changePassword(id, pass);
  });
});
  listEl.querySelectorAll('button.del').forEach(btn => btn.addEventListener('click', () => deleteEntry(btn.getAttribute('data-id'))));
}
// Historia: pokaż/ukryj
listEl.querySelectorAll('button.hist-reveal').forEach(btn => {
  btn.addEventListener('click', () => {
    const id = btn.dataset.id, idx = btn.dataset.idx;
    const input = listEl.querySelector(`input.hist[data-id="${id}"][data-idx="${idx}"]`);
    if (!input) return;
    if (input.type === 'password'){ input.type='text'; btn.textContent='Ukryj'; }
    else { input.type='password'; btn.textContent='Pokaż'; }
  });
});
// Historia: kopiuj
listEl.querySelectorAll('button.hist-copy').forEach(btn => {
  btn.addEventListener('click', async () => {
    const id = btn.dataset.id, idx = btn.dataset.idx;
    const input = listEl.querySelector(`input.hist[data-id="${id}"][data-idx="${idx}"]`);
    try{ await navigator.clipboard.writeText(input.value||''); alert('Skopiowano stare hasło.'); }
    catch{ alert('Nie udało się skopiować.'); }
  });
});
// Historia: przywróć
listEl.querySelectorAll('button.hist-restore').forEach(btn => {
  btn.addEventListener('click', () => {
    const id = btn.dataset.id, idx = Number(btn.dataset.idx);
    const e = vault.entries.find(x => x.id === id); if (!e || !e.history || !e.history[idx]) return;
    const pw = e.history[idx].password;
    changePassword(id, pw); // przywrócenie też trafi obecne hasło do historii
  });
});

function addEntry(){ ensureUnlocked(); const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now()+Math.random()); const now=nowIso();
  vault.entries.unshift({ id, title:'Nowy wpis', username:'', password:'', url:'', notes:'', createdAt: now, updatedAt: now, pwChangedAt: now });
  renderList(); persistVault();
}
function updateEntry(id, patch){ const e = vault.entries.find(x => x.id===id); if(!e) return; Object.assign(e, patch); e.updatedAt = nowIso(); persistVault(); }
function deleteEntry(id){ if(!confirm('Usunąć ten wpis?')) return; vault.entries = vault.entries.filter(x => x.id !== id); renderList(); persistVault(); }

// ================== Generator ==================
function generatePassword(){
  const len = Math.max(6, Math.min(128, parseInt(genLen.value,10) || 16));
  let pool=''; if (genLower.checked) pool+='abcdefghijkmnopqrstuvwxyz'; if (genUpper.checked) pool+='ABCDEFGHJKLMNPQRSTUVWXYZ'; if (genDigits.checked) pool+='23456789'; if (genSymbols.checked) pool+='!@#$%^&*()-_=+[]{};:,.?/';
  if (!pool) pool='abcdefghijkmnopqrstuvwxyz';
  const arr = new Uint32Array(len); crypto.getRandomValues(arr);
  let out=''; for(let i=0;i<len;i++) out+=pool[arr[i] % pool.length];
  genOut.value=out; const m = measureStrength(out, []); updateMeter('genMeterBar','genMeterLabel', m); return out;
}
genBtn?.addEventListener('click', generatePassword);
genCopy?.addEventListener('click', async () => { try{ await navigator.clipboard.writeText(genOut.value||''); genCopied.hidden=false; setTimeout(()=> genCopied.hidden=true,1200);} catch{ alert('Nie udało się skopiować.'); } });

// ================== Miernik siły ==================
function measureStrength(pw, ctx=[]){
  const res={score:0,label:'—',width:0,tips:[]}; if(!pw) return {score:0,label:'Puste',width:0,tips:['Wpisz hasło.']};
  const len=pw.length, hasLower=/[a-z]/.test(pw), hasUpper=/[A-Z]/.test(pw), hasDigit=/\d/.test(pw), hasSym=/[^A-Za-z0-9]/.test(pw);
  let pts=0; if(len>=8)pts++; if(len>=12)pts++; if(len>=16)pts++; pts += [hasLower,hasUpper,hasDigit,hasSym].filter(Boolean).length-1;
  if (/(.)\1{2,}/.test(pw)){ pts-=1; res.tips.push('Unikaj powtórzeń.'); }
  if (/abc|qwe|123|987|password|haslo/i.test(pw)){ pts-=1; res.tips.push('Unikaj sekwencji.'); }
  const low=pw.toLowerCase(); for(const w of ctx){ const s=String(w||'').toLowerCase(); if(s.length>=3 && low.includes(s)){ pts-=1; res.tips.push('Zawiera dane z wpisu.'); break; } }
  let score=Math.max(0,Math.min(4,pts)); if(len<12){ score=Math.min(score,1); res.tips.push('Dłuższe (12+).'); } if([hasLower,hasUpper,hasDigit,hasSym].filter(Boolean).length<=1){ score=Math.min(score,1); res.tips.push('Więcej typów znaków.'); }
  res.score=score; res.label=['Bardzo słabe','Słabe','OK','Dobre','Bardzo dobre'][score]; res.width=(score/4)*100; return res;
}
function updateMeter(barId,labelId,m){ const bar=document.getElementById(barId), lab=document.getElementById(labelId); if(!bar||!lab) return; bar.style.width=`${m.width}%`; lab.textContent=`${m.label}${m.tips&&m.tips.length?' · '+m.tips[0]:''}`; }
// Render sekcji „Historia haseł” dla jednego wpisu
function renderHistory(e){
  if (!e.history || !e.history.length) return '';
  return `<details class="pw-hist">
    <summary>Ostatnie hasła (${e.history.length})</summary>
    ${e.history.map((h, idx) => `
      <div class="row tight">
        <input type="password" class="hist" data-id="${e.id}" data-idx="${idx}" value="${escapeHtml(h.password)}" readonly>
        <button type="button" class="secondary hist-reveal"  data-id="${e.id}" data-idx="${idx}">Pokaż</button>
        <button type="button" class="secondary hist-copy"    data-id="${e.id}" data-idx="${idx}">Kopiuj</button>
        <button type="button" class="ghost hist-restore"     data-id="${e.id}" data-idx="${idx}">Przywróć</button>
        <span class="muted">${new Date(h.changedAt).toLocaleString()}</span>
      </div>
    `).join('')}
  </details>`;
}

// Zmiana hasła z potwierdzeniem + historia
function changePassword(id, newPw, opts={}){
  ensureUnlocked();
  const e = vault.entries.find(x => x.id === id); if(!e) return;
  const old = e.password || '';
  if (old === newPw) return;

  if (settings.protectPwChange && opts.confirm !== false){
    const t = e.title || '(bez tytułu)';
    if (!confirm(`Zamienić hasło w „${t}”? Poprzednie trafi do historii.`)) return;
  }

  if (old){
    e.history = e.history || [];
    e.history.unshift({ password: old, changedAt: nowIso() });
    e.history = e.history.slice(0, settings.historySize || 3);
  }
  e.password = newPw;
  e.pwChangedAt = nowIso();
  e.updatedAt = nowIso();
  persistVault();
  renderList();
}

// ================== Audyt ==================
function runAudit(){
  ensureUnlocked();
  const entries=vault.entries, byPassword=new Map();
  for(const e of entries){ const p=e.password||''; if(!byPassword.has(p)) byPassword.set(p,[]); byPassword.get(p).push(e); }
  const duplicates=[]; for(const [pass,arr] of byPassword.entries()){ if(!pass) continue; if(arr.length>=2) duplicates.push(arr.map(x=>x.title||'(bez tytułu)')); }
  const tooShort=entries.filter(e => (e.password||'').length && e.password.length<12).map(e=>e.title||'(bez tytułu)');
  const oldOnes=[]; for(const e of entries){ const when=e.pwChangedAt||e.updatedAt||e.createdAt||nowIso(); const d=daysBetween(when); if((e.password||'').length && d>(settings.ageDays||180)) oldOnes.push({title:e.title||'(bez tytułu)',days:d}); }
  const weakOnes=[]; for(const e of entries){ const m=measureStrength(e.password||'', entryContext(e.id)); if((e.password||'').length && m.score<=1) weakOnes.push({title:e.title||'(bez tytułu)',note:m.label}); }

  const out=[];
  if(!entries.length) out.push(`<div class="audit-item"><span class="muted">Brak wpisów do audytu.</span></div>`);
  else{
    out.push(duplicates.length ? `<div class="audit-item bad"><strong>Powtórki haseł (${duplicates.length})</strong><ul>${duplicates.map(g=>`<li>${g.map(escapeHtml).join(' · ')}</li>`).join('')}</ul></div>` : `<div class="audit-item good"><strong>Brak powtórek haseł ✔</strong></div>`);
    out.push(tooShort.length ? `<div class="audit-item warn"><strong>Zbyt krótkie (&lt;12): ${tooShort.length}</strong><ul>${tooShort.map(t=>`<li>${escapeHtml(t)}</li>`).join('')}</ul></div>` : `<div class="audit-item good"><strong>Brak zbyt krótkich ✔</strong></div>`);
    out.push(oldOnes.length ? `<div class="audit-item warn"><strong>Stare hasła &gt; ${settings.ageDays} dni: ${oldOnes.length}</strong><ul>${oldOnes.map(o=>`<li>${escapeHtml(o.title)} <span class="muted">(${o.days} dni)</span></li>`).join('')}</ul></div>` : `<div class="audit-item good"><strong>Brak starych haseł ✔</strong></div>`);
    out.push(weakOnes.length ? `<div class="audit-item warn"><strong>Słabe wg miernika: ${weakOnes.length}</strong><ul>${weakOnes.map(w=>`<li>${escapeHtml(w.title)} <span class="muted">(${escapeHtml(w.note)})</span></li>`).join('')}</ul></div>` : `<div class="audit-item good"><strong>Brak słabych ✔</strong></div>`);
  }
  auditResults.innerHTML=out.join('');
}

// ================== Search / add / lock ==================
addEntryBtn?.addEventListener('click', addEntry);
lockBtn?.addEventListener('click', lockApp);
searchEl?.addEventListener('input', ()=>{ if(vault) renderList(); });
runAuditBtn?.addEventListener('click', runAudit);

// Delegacja klików dla przycisków w Historii haseł (działa po każdym renderze)
listEl?.addEventListener('click', async (e) => {
  const btnReveal  = e.target.closest('button.hist-reveal');
  const btnCopy    = e.target.closest('button.hist-copy');
  const btnRestore = e.target.closest('button.hist-restore');
  if (!btnReveal && !btnCopy && !btnRestore) return;

  e.preventDefault(); // nic nie propaguj dalej (szczególnie w <details>)
  const btn = btnReveal || btnCopy || btnRestore;
  const id  = btn.dataset.id;
  const idx = btn.dataset.idx;
  const input = listEl.querySelector(`input.hist[data-id="${id}"][data-idx="${idx}"]`);
  if (!input) return;

  if (btnReveal){
    if (input.type === 'password'){ input.type = 'text';  btn.textContent = 'Ukryj'; }
    else                          { input.type = 'password'; btn.textContent = 'Pokaż'; }
    return;
  }

  if (btnCopy){
    try{
      await navigator.clipboard.writeText(input.value || '');
      alert('Skopiowano stare hasło.');
    }catch{
      const ta = document.createElement('textarea');
      ta.value = input.value || ''; document.body.appendChild(ta);
      ta.select();
      try{ document.execCommand('copy'); alert('Skopiowano stare hasło.'); }
      catch{ alert('Nie udało się skopiować.'); }
      document.body.removeChild(ta);
    }
    return;
  }

  if (btnRestore){
    const eTitle = (vault.entries.find(x=>x.id===id)?.title) || '(bez tytułu)';
    if (!confirm(`Przywrócić to hasło w „${eTitle}”? Obecne trafi do historii.`)) return;
    changePassword(id, input.value, { confirm: false }); // changePassword sam dopisze historię
    return;
  }
});

// ================== Export / Import ==================
exportBtn?.addEventListener('click', () => {
  ensureUnlocked();
  const payload = { meta, blob: JSON.parse(localStorage.getItem(BLOB_KEY)) };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download='vault_encrypted.json'; a.click(); URL.revokeObjectURL(url);
});
chooseFileBtn?.addEventListener('click', ()=> importFile.click());
importFile?.addEventListener('change', ()=>{ const name=importFile.files?.[0]?.name || 'Brak pliku'; fileNameEl && (fileNameEl.textContent=name); });
importBtn?.addEventListener('click', async ()=>{
  const file=importFile.files?.[0]; if(!file){ alert('Wybierz plik .json.'); return; }
  const text=await file.text(); try{
    const parsed=JSON.parse(text);
    if(!parsed?.meta?.salt || !parsed?.blob?.ciphertext || !parsed?.blob?.iv) throw new Error('zły format');
    localStorage.setItem(META_KEY, JSON.stringify(parsed.meta));
    localStorage.setItem(BLOB_KEY, JSON.stringify(parsed.blob));
    meta = parsed.meta; alert('Zaimportowano. Odblokuj hasłem z importu.'); lockApp();
  }catch{ alert('Nieprawidłowy plik importu.'); }
});

// ================== Face ID / Touch ID ==================
async function hasPasskeySupport(){
  if (!window.PublicKeyCredential || !window.isSecureContext) return false;
  try{ return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch { return false; }
}
function passkeyConfigured(){ return !!localStorage.getItem(PASSKEY_ID_KEY) && !!localStorage.getItem(QUICK_BLOB_KEY); }
function updatePasskeyState(){
  const ok = passkeyConfigured();
  if (passkeyState) passkeyState.textContent = ok ? 'Skonfigurowane na tym urządzeniu' : 'Nie skonfigurowane';
  updateBioUI();
}
function updateBioUI(){
  const can = passkeyConfigured();
  if (bioUnlockBtn) bioUnlockBtn.hidden = !can;
  if (bioHint){
    if (!can) bioHint.textContent = 'Tip: włącz Face ID w Ustawieniach, aby odblokowywać bez hasła.';
    else bioHint.textContent = 'Możesz użyć Face ID, aby szybko odblokować.';
  }
}

async function passkeyRegister(){
  if (!(await hasPasskeySupport())){ alert('To urządzenie/przeglądarka nie obsługuje biometrii WebAuthn.'); return; }
  if (!masterKey){ alert('Najpierw odblokuj sejf hasłem, potem włącz Face ID.'); return; }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    challenge,
    rp: { name:'Lokalny Magazyn Haseł', id: location.hostname },
    user: { id: userId, name: 'local-user', displayName: 'Local User' },
    pubKeyCredParams: [{ type:'public-key', alg: -7 }, { type:'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment:'platform', userVerification:'required', residentKey:'preferred' },
    timeout: 60_000,
    extensions: { prf: { enable: true } } // prosimy o PRF
  };
  const cred = await navigator.credentials.create({ publicKey: pubKey });
  if (!cred) { alert('Nie udało się utworzyć poświadczenia.'); return; }

  // zapisz identyfikatory lokalnie
  localStorage.setItem(PASSKEY_ID_KEY, b64url(cred.rawId));
  localStorage.setItem(PASSKEY_USER_ID_KEY, b64url(userId));

  // pozyskaj tajemnicę PRF z get() i z niej wyprowadź klucz AES
  quickKey = await deriveDeviceKeyFromPasskey(cred.rawId);

  // zapisz kopię sejfu szyfrowaną kluczem z Face ID
  await persistVault();

  alert('Face ID skonfigurowane. Od teraz możesz odblokowywać bez hasła.');
  updatePasskeyState();
}

async function deriveDeviceKeyFromPasskey(rawId){
  const allow = [{ id: rawId, type:'public-key' }];
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: allow,
      userVerification: 'required',
      extensions: { prf: { eval: { first: PASSKEY_SALT } } }
    },
    mediation: 'optional'
  });
  const exts = assertion.getClientExtensionResults?.();
  const prf = exts && exts.prf && exts.prf.results && exts.prf.results.first;
  if (!prf) throw new Error('PRF extension niedostępne – szybkie odblokowanie nieobsługiwane.');
  return prfToAesKey(prf);
}

async function quickUnlock(){
  try{
    if (!await hasPasskeySupport()) { alert('Brak wsparcia biometrii na tym urządzeniu.'); return; }
    const id = localStorage.getItem(PASSKEY_ID_KEY); const qb = localStorage.getItem(QUICK_BLOB_KEY);
    if (!id || !qb){ alert('Face ID nie skonfigurowane.'); return; }

    const rawId = fromB64url(id);
    quickKey = await deriveDeviceKeyFromPasskey(rawId.buffer);
    const payload = JSON.parse(qb);
    vault = await decryptJson(payload, quickKey);
    showMain();
  }catch(e){
    console.error(e);
    quickKey = null; alert('Nie udało się odblokować przez Face ID.');
  }
}

async function passkeyRemove(){
  if (!passkeyConfigured()){ alert('Face ID nie jest skonfigurowane.'); return; }
  if (!confirm('Wyłączyć szybkie odblokowanie na tym urządzeniu?')) return;
  localStorage.removeItem(PASSKEY_ID_KEY);
  localStorage.removeItem(PASSKEY_USER_ID_KEY);
  localStorage.removeItem(QUICK_BLOB_KEY);
  quickKey = null;
  updatePasskeyState();
  alert('Wyłączono Face ID dla tego urządzenia.');
}

// UI biometrii
passkeySetupBtn?.addEventListener('click', passkeyRegister);
passkeyRemoveBtn?.addEventListener('click', passkeyRemove);
bioUnlockBtn?.addEventListener('click', quickUnlock);

// ================== Maska ekranów ==================
function showMask(){
  if (settings.maskEnabled){
    privacyMask?.removeAttribute('hidden');
    document.documentElement.classList.add('masked');
  }
}
function hideMask(){
  privacyMask?.setAttribute('hidden','');
  document.documentElement.classList.remove('masked');
}

// ——— ZDJĘCIE MASKI po powrocie ———
function onShow(){ hideMask(); }
function onHide(){ showMask(); }

// iOS PWA lub przełączanie kart: ustaw/ściągnij maskę pewnie
document.addEventListener('visibilitychange', ()=> { if (document.hidden) onHide(); else onShow(); });
window.addEventListener('pagehide', onHide);   // gdy strona idzie w tło
window.addEventListener('blur', onHide);
window.addEventListener('focus', onShow);
window.addEventListener('pageshow', onShow);   // gdy wraca do przodu

// Ekran blokady: każda interakcja też zdejmuje maskę (na wszelki wypadek)
['pointerdown','touchstart','click','keydown','focusin'].forEach(ev => {
  lockView?.addEventListener(ev, onShow, { passive:true });
});

// Klik Face ID: zdejmij maskę i „obudź” aktywność
bioUnlockBtn?.addEventListener('click', onShow, { capture:true });

// ================== Init ==================
applyTheme();
loadSettings();
checkSetup();
showTab('vault');

// Wyzeruj poziomy scroll na starcie i przy resize (iOS czasem przesuwa)
function resetScrollX(){ document.documentElement.scrollLeft = 0; document.body.scrollLeft = 0; }
window.addEventListener('load', resetScrollX);
window.addEventListener('resize', resetScrollX);

// ================== PWA (opcjonalnie) ==================
if ('serviceWorker' in navigator){
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(()=>{ /* cicho */ });
  });
}