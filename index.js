require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser'); // on garde body-parser pour tout sauf le webhook Stripe (RAW)
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const goCardless = require('gocardless-nodejs');
const cookieParser = require('cookie-parser');
const { URLSearchParams } = require('url');
const multer = require('multer');
const cryptoNode = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-super-secret';

// === Admin (OptiAdmin) – Auth dédiée ===
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';        // ex: admin@opticom.fr
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';  // ex: très long, stocké en env
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET;

function signAdmin(payload, expiresIn = '12h') {
  return jwt.sign(payload, ADMIN_JWT_SECRET, { algorithm: 'HS256', expiresIn });
}
function verifyAdmin(token) {
  try { return jwt.verify(token, ADMIN_JWT_SECRET); } catch { return null; }
}
function requireAdmin(req, res, next) {
  const auth = (req.get('authorization') || '').split(' ')[1] || '';
  const dec = verifyAdmin(auth);
  if (!dec || dec.role !== 'admin') return res.status(401).json({ error: 'unauthorized' });
  next();
}



// --- Routes/Services externes existants
const licenceRoutes = require('./routes/licence.routes');
const purgeRoutes = require('./routes/purge.routes');
const { schedulePurge } = require('./services/purgeService');

// --- JSONBin (BIN licences)
const JSONBIN_BIN_ID = process.env.JSONBIN_BIN_ID;
const JSONBIN_KEY = process.env.JSONBIN_MASTER_KEY || process.env.JSONBIN_API_KEY;

// --- CGV
const CGV_VERSION = process.env.CGV_VERSION || '2025-08-14';
const CGV_FILE = path.join(__dirname, 'public', 'legal', `cgv-${CGV_VERSION}.md`);

let CGV_TEXT_HASH = process.env.CGV_TEXT_HASH || '';
try {
  const cgvTxt = fs.readFileSync(CGV_FILE, 'utf8');
  CGV_TEXT_HASH = cryptoNode.createHash('sha256').update(cgvTxt).digest('hex');
  console.log('✅ CGV loaded:', CGV_FILE, 'hash=', CGV_TEXT_HASH);
} catch (e) {
  console.warn('⚠️ CGV file not found. You can still use env CGV_TEXT_HASH if provided.');
}

// --- Node 18+ : fetch natif
const fetch = globalThis.fetch.bind(globalThis);

const app = express();

// --- Metrics ultra-simples
const metrics = { byPath: new Map() };
app.use((req, _res, next) => {
  const key = `${req.method} ${req.path}`;
  metrics.byPath.set(key, (metrics.byPath.get(key) || 0) + 1);
  next();
});
app.get('/__metrics', (_req, res) => {
  const jm = global.__METRICS__ || { jsonbinGets: 0, jsonbinPuts: 0, cacheHits: 0, cacheMiss: 0 };
  res.json({
    jsonbin: { gets: jm.jsonbinGets, puts: jm.jsonbinPuts, cacheHits: jm.cacheHits, cacheMiss: jm.cacheMiss },
    byPath: Object.fromEntries(metrics.byPath),
    now: new Date().toISOString()
  });
});

// --- Petit burst limiter défensif
function makeBurstLimiter({ limit = 6, windowMs = 10_000 } = {}) {
  const buckets = new Map();
  return (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    const key = `${req.path}|${req.ip}`;
    const now = Date.now();
    const arr = buckets.get(key) || [];
    while (arr.length && now - arr[0] > windowMs) arr.shift();
    if (arr.length >= limit) {
      const retry = Math.ceil((windowMs - (now - arr[0])) / 1000);
      res.set('Retry-After', String(retry));
      return res.status(429).json({ error: 'RATE_LIMITED', retryAfterSec: retry });
    }
    arr.push(now);
    buckets.set(key, arr);
    next();
  };
}
const burstLimiter = makeBurstLimiter({ limit: 6, windowMs: 10_000 });

app.set('trust proxy', 1); // important derrière Render/NGINX
const PORT = process.env.PORT || 3001;

// --- Stripe / GoCardless
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const GO_CARDLESS_API_BASE = 'https://api.gocardless.com';
const goCardlessClient = goCardless(
  process.env.GOCARDLESS_API_KEY,
  { environment: process.env.GOCARDLESS_ENV || 'live' } // ✅ correct
);

// --- Sessions simples en mémoire
const sessionTokenMap = new Map();

// --- Formules
const formulas = [
  { id: 'starter', name: 'Starter', credits: 100 },
  { id: 'pro', name: 'Pro', credits: 300 },
  { id: 'premium', name: 'Premium', credits: 600 },
  { id: 'alacarte', name: 'À la carte', credits: 0 }
];

// --- Dossier factures public
const factureDir = path.join(__dirname, 'public/factures');
if (!fs.existsSync(factureDir)) fs.mkdirSync(factureDir, { recursive: true });

app.use(
  '/factures',
  express.static(factureDir, {
    index: false,
    maxAge: '1y',
    setHeaders: (res) => {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.setHeader('Content-Disposition', 'inline');
    }
  })
);

// --- CORS dynamique
const allowedOrigins = [
  'https://opticom-web.vercel.app',
  'https://opti-admin.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000'
];
const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); // cURL / Postman
    const ok = allowedOrigins.includes(origin);
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], // <- PUT ajouté
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
};
app.use((req, res, next) => { res.setHeader('Vary', 'Origin'); next(); });
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions)); // préflights

// --- Cookies
app.use(cookieParser());

// ⛔️ Stripe exige RAW: on évite le JSON parser sur /webhook-stripe
app.use((req, res, next) => {
  if (req.originalUrl && req.originalUrl.startsWith('/webhook-stripe')) return next();
  return bodyParser.json({ limit: '2mb' })(req, res, next);
});

// --- Statiques généraux
app.use('/public', express.static('public'));

// --- Légal (sert /legal/*.md depuis public/legal)
app.use(
  '/legal',
  express.static(path.join(__dirname, 'public', 'legal'), {
    index: false,
    maxAge: '1y',
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.md')) {
        res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      }
    },
  })
);


// --- Route de test JSONBin data (temporaire, si présente)
try {
  app.use(require('./routes/_devJsonbinTest'));
} catch (e) {
  // silencieux si la route n'existe pas en prod
}

// --- Routes modules existants
app.use('/api', licenceRoutes);
app.use('/api', purgeRoutes);

// --- CRON purge quotidienne (03:00 Europe/Paris)
schedulePurge();

// --- Ping
app.get('/', (_req, res) => res.json({
  ok: true,
  service: 'opticom-sms-server',
  node: process.version,
  time: new Date().toISOString()
}));

// ===== Upload facture PDF (protégé par token)
const ADMIN_UPLOAD_TOKEN = process.env.ADMIN_UPLOAD_TOKEN;
function requireAdminToken(req, res, next) {
  if (!ADMIN_UPLOAD_TOKEN) return res.status(500).json({ error: 'ADMIN_UPLOAD_TOKEN manquant côté serveur' });
  const auth = req.get('authorization') || '';
  if (auth !== `Bearer ${ADMIN_UPLOAD_TOKEN}`) return res.status(401).json({ error: 'unauthorized' });
  next();
}
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, factureDir),
  filename: (req, _file, cb) => {
    const numero = (req.body.numero && String(req.body.numero).trim()) || uuidv4();
    const safe = numero.replace(/[^A-Za-z0-9-_]/g, '_');
    cb(null, `${safe}.pdf`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, file.mimetype === 'application/pdf')
});
app.post('/api/upload-facture', requireAdminToken, upload.single('pdf'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier PDF manquant (champ 'pdf')." });
  const numero = String(req.body.numero || path.basename(req.file.filename, '.pdf'));
  const url = `${req.protocol}://${req.get('host')}/factures/${req.file.filename}`;
  res.json({ ok: true, numero, filename: req.file.filename, url });
});

// =======================
//   JSONBIN HELPERS (BIN licences)
// =======================
// ==== Metrics & Cache JSONBin (drop-in) ====
// Compteurs globaux (réutilisés si déjà présents)
const __METRICS__ = (global.__METRICS__ = global.__METRICS__ || {
  jsonbinGets: 0,
  jsonbinPuts: 0,
  cacheHits: 0,
  cacheMiss: 0,
});

// TTL du cache (ms) – ajuste via env si besoin
const JSONBIN_CACHE_TTL_MS = Number(process.env.JSONBIN_CACHE_TTL_MS || 15000);

// Cache en mémoire + dédoublonnage des GET en vol
let __jsonbinCache = { data: null, expires: 0 };
let __jsonbinInflight = null;

const must = (v, name) => { if (!v) throw new Error(`${name} manquant.`); return v; };

async function jsonbinGetAll(force = false) {
  const binId = must(JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const now = Date.now();

  // Cache hit ?
  if (!force && __jsonbinCache.data && now < __jsonbinCache.expires) {
    __METRICS__.cacheHits++;
    return __jsonbinCache.data;
  }

  __METRICS__.cacheMiss++;

  // Requêtes concurrentes : on partage la même promesse
  if (__jsonbinInflight) {
    try { return await __jsonbinInflight; } finally {}
  }

  const headers = { 'X-Bin-Meta': 'false' };
  if (JSONBIN_KEY) headers['X-Master-Key'] = JSONBIN_KEY;

  __jsonbinInflight = (async () => {
    __METRICS__.jsonbinGets++;
    const r = await fetch(`https://api.jsonbin.io/v3/b/${binId}/latest`, { headers });
    if (!r.ok) {
      const t = await r.text().catch(() => '');
      throw new Error(`Erreur JSONBin (${r.status}): ${t}`);
    }
    const data = await r.json();
    const record = data?.record ?? data;
    const list = Array.isArray(record) ? record : (record ? [record] : []);


    const payload = { list, rawRecord: record };
    __jsonbinCache = { data: payload, expires: now + JSONBIN_CACHE_TTL_MS };
    return payload;
  })();

  try {
    return await __jsonbinInflight;
  } finally {
    __jsonbinInflight = null;
  }
}

async function jsonbinPutAll(body) {
  const binId = must(JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const headers = { 'Content-Type': 'application/json', 'X-Bin-Versioning': 'false' };
  if (JSONBIN_KEY) headers['X-Master-Key'] = JSONBIN_KEY;

  __METRICS__.jsonbinPuts++;
  const r = await fetch(`https://api.jsonbin.io/v3/b/${binId}`, {
    method: 'PUT',
    headers,
    body: JSON.stringify(body)
  });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`Erreur mise à jour JSONBin: ${t}`);
  }

  // ✅ On met à jour le cache local immédiatement après un PUT réussi
  const rawRecord = body;
  const list = Array.isArray(body) ? body : [body];
  __jsonbinCache = {
    data: { list, rawRecord },
    expires: Date.now() + JSONBIN_CACHE_TTL_MS,
  };
}

function findLicenceIndex(list, predicate) {
  const idx = list.findIndex(predicate);
  return { idx, licence: idx >= 0 ? list[idx] : null };
}
function findLicenceIndexByAnyId(list, licenceId) {
  const K = String(licenceId || '').trim();
  return findLicenceIndex(
    list,
    (l) =>
      String(l.id || '').trim() === K ||
      String(l.licence || '').trim() === K ||
      String(l.opticien?.id || '').trim() === K
  );
}

// --- Serialize JSONBin writes & always merge on latest snapshot ---
// ⚠️ Nouveau: mutation sur un CLONE, cache mis à jour uniquement si PUT OK
let __jsonbinWriteChain = Promise.resolve();

/**
 * Exécute mutator sur un clone du dernier état (force=true), sérialise les écritures,
 * et fait un PUT unique. Le mutator DOIT muter `draft.list` in-place.
 * Retourne la valeur du mutator. Pour annuler la sauvegarde, retourne { __skipSave: true }.
 */
async function withJsonbinUpdate(mutator) {
  let out;
  __jsonbinWriteChain = __jsonbinWriteChain.then(async () => {
    // 1) Récupère l'état le + récent (bypass cache)
    const latest = await jsonbinGetAll(true);

    // 2) Clone profond pour éviter de muter le cache tant que le PUT n'est pas OK
    const draft = {
      rawRecord: Array.isArray(latest.rawRecord)
        ? latest.rawRecord.map(x => JSON.parse(JSON.stringify(x)))
        : JSON.parse(JSON.stringify(latest.rawRecord)),
      list: latest.list.map(x => JSON.parse(JSON.stringify(x))),
    };

    // 3) Mutation côté appelant
    out = (await mutator(draft)) || {};
    if (out.__skipSave) return;

    // 4) Calcule la forme à persister selon le schéma du bin (array vs objet)
    const toPut = Array.isArray(latest.rawRecord) ? draft.list : (draft.list[0] || {});

    // 5) Sauvegarde sur JSONBin
    await jsonbinPutAll(toPut);

    // 6) Si OK, le cache global est déjà mis à jour par jsonbinPutAll().
    // Rien d'autre à faire ici.
  }).catch((e) => {
    console.error('withJsonbinUpdate failed:', e);
    throw e;
  });

  await __jsonbinWriteChain;
  return out;
}





// (facultatif) expose les métriques si tu veux les lire depuis une route /__metrics
module.exports.__JSONBIN_METRICS__ = __METRICS__;

function mergeWithProtection(oldObj = {}, patch = {}, allowKeys = []) {
  const allow = new Set(allowKeys);
  const out = { ...oldObj };
  for (const [k, v] of Object.entries(patch || {})) {
    if (PROTECTED_FIELDS.has(k) && !allow.has(k)) continue; // on ignore toute tentative d'écraser
    out[k] = v;
  }
  out.updatedAt = new Date().toISOString();
  return out;
}

function signToken(payload, expiresIn = '30d') {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn });
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
async function getLicenceByIdOrKey({ licenceId, cle }) {
  const { list } = await jsonbinGetAll();
  const { idx, licence } = findLicenceIndex(list, l =>
    (licenceId && String(l.id) === String(licenceId)) ||
    (cle && normKey(l.licence || l.cle || l.key) === normKey(cle))
  );
  return { idx, licence, list };
}


// =======================
//   Licence update helper
// =======================

// Champs protégés: jamais écrasés par une sync générique
const PROTECTED_FIELDS = new Set([
  'libelleExpediteur', 'signature',
  'historiqueSms', 'smsHistoryTombstones' // ← historique & tombstones
]);

function stripProtectedFields(patch = {}, allowKeys = []) {
  const allow = new Set(allowKeys);
  const out = {};
  for (const [k, v] of Object.entries(patch || {})) {
    if (PROTECTED_FIELDS.has(k) && !allow.has(k)) continue; // on ignore
    out[k] = v;
  }
  return out;
}

async function updateLicenceFields({ licenceId, opticienId, patch = {}, allowKeys = [] }) {
  const { list, rawRecord } = await jsonbinGetAll();

  const { idx, licence } = findLicenceIndex(
    list,
    (l) =>
      (licenceId && String(l.id) === String(licenceId)) ||
      (opticienId && String(l.opticien?.id) === String(opticienId))
  );
  if (idx === -1 || !licence) return { ok:false, status:404, error:'LICENCE_NOT_FOUND' };

  const safePatch = stripProtectedFields(patch, allowKeys);
  const updated = { ...licence, ...safePatch, updatedAt: new Date().toISOString() };

  // ⚠️ si on a explicitement le droit de modifier historiqueSms on garde l’existant fusionné
  if (allowKeys.includes('historiqueSms') && Array.isArray(patch.historiqueSms)) {
    updated.historiqueSms = patch.historiqueSms;
  }

  const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = updated, list) : updated;
  await jsonbinPutAll(bodyToPut);

  return { ok:true, licence: updated };
}

function normalizeSenderUpper(raw = '') {
  let s = String(raw).toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (s.length < 3) s = 'OPTICOM';
  if (s.length > 11) s = s.slice(0, 11);
  return s;
}

function normKey(s=''){ return String(s).replace(/[\s-]/g,'').toUpperCase(); }

function findLicenceIdxByRefs(list, { licenceId, cle, opticienId }) {
  const byId  = l => licenceId  && String(l.id) === String(licenceId);
  const byCle = l => cle && normKey(l.licence || l.cle || l.key) === normKey(cle);
  const byOpt = l => opticienId && String(l.opticien?.id) === String(opticienId);

  let idx = list.findIndex(l => byId(l) || byCle(l) || byOpt(l));
  if (idx >= 0) return { idx, licence: list[idx] };

  if (licenceId && !cle) { // fallback si "licenceId" contient en fait la clé
    idx = list.findIndex(l => normKey(l.licence || l.cle || l.key) === normKey(licenceId));
    if (idx >= 0) return { idx, licence: list[idx] };
  }
  return { idx: -1, licence: null };
}

// =======================
//   Licence: expéditeur & signature (POST+PUT, avec alias /api)
//   -> tolère plusieurs noms de champs et récupère licenceId de plusieurs façons
// =======================
function pickStr(...vals) {
  for (const v of vals) {
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}
async function resolveLicenceIdFromAny(b, q) {
  // Priorité: id direct, sinon cle/licence -> recherche
  const direct = pickStr(b.licenceId, q.licenceId, b.id);
  if (direct) return direct;
  const key = pickStr(b.cle, q.cle, b.key, b.licence);
  if (!key) return '';
  const lic = await findLicence({ cle: key }); // ta fonction existante plus bas
  return lic?.id || '';
}

async function handleSaveSender(req, res) {
  try {
    const b = req.body || {}, q = req.query || {};
    const libelleInput = String(b.libelleExpediteur ?? b.sender ?? b.expediteur ?? q.libelleExpediteur ?? '').trim();
    if (!libelleInput) return res.status(400).json({ success: false, error: 'LIBELLE_MANQUANT' });

    const refs = {
      licenceId: String(b.licenceId ?? q.licenceId ?? b.id ?? '').trim() || undefined,
      cle:       String(b.cle ?? q.cle ?? b.licence ?? '').trim() || undefined,
      opticienId:String(b.opticienId ?? q.opticienId ?? '').trim() || undefined,
    };

    const cleaned = normalizeSenderUpper(libelleInput);

    const result = await withJsonbinUpdate(async ({ list }) => {
      const { idx, licence } = findLicenceIdxByRefs(list, refs);
      if (idx === -1 || !licence) return { __skipSave: true, status: 404, error: 'LICENCE_NOT_FOUND' };

      licence.libelleExpediteur = cleaned;
      // compat ancien schéma
      licence.expediteur = cleaned;
      licence.updatedAt = new Date().toISOString();

      list[idx] = licence; // mutation in-place
      return { licence };
    });

    if (result?.status === 404) return res.status(404).json({ success: false, error: 'LICENCE_NOT_FOUND' });
    return res.json({ success: true, licence: result.licence });
  } catch (e) {
    console.error('❌ /licence/expediteur error:', e);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
}

async function handleSaveSignature(req, res) {
  try {
    const b = req.body || {}, q = req.query || {};
    const signature = String(b.signature ?? q.signature ?? '').trim().slice(0, 200);
    if (!signature) return res.status(400).json({ success: false, error: 'SIGNATURE_MANQUANTE' });

    const refs = {
      licenceId: String(b.licenceId ?? q.licenceId ?? b.id ?? '').trim() || undefined,
      cle:       String(b.cle ?? q.cle ?? b.licence ?? '').trim() || undefined,
      opticienId:String(b.opticienId ?? q.opticienId ?? '').trim() || undefined,
    };

    const result = await withJsonbinUpdate(async ({ list }) => {
      const { idx, licence } = findLicenceIdxByRefs(list, refs);
      if (idx === -1 || !licence) return { __skipSave: true, status: 404, error: 'LICENCE_NOT_FOUND' };

      licence.signature = signature;
      licence.updatedAt = new Date().toISOString();

      list[idx] = licence; // mutation in-place
      return { licence };
    });

    if (result?.status === 404) return res.status(404).json({ success: false, error: 'LICENCE_NOT_FOUND' });
    return res.json({ success: true, licence: result.licence });
  } catch (e) {
    console.error('❌ /licence/signature error:', e);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
}
// Sender
app.post('/licence/expediteur', handleSaveSender);
app.put ('/licence/expediteur', handleSaveSender);
app.post('/api/licence/expediteur', handleSaveSender);
app.put ('/api/licence/expediteur', handleSaveSender);

// Signature
app.post('/licence/signature', handleSaveSignature);
app.put ('/licence/signature', handleSaveSignature);
app.post('/api/licence/signature', handleSaveSignature);
app.put ('/api/licence/signature', handleSaveSignature);

// ✅ Bootstrap expéditeur + signature en une fois
app.post('/api/licence/bootstrap', async (req, res) => {
  try {
    const { licenceId, libelleExpediteur, signature } = req.body || {};
    if (!licenceId) return res.status(400).json({ ok:false, error:'LICENCE_ID_REQUIS' });

    const cleanedSender = libelleExpediteur ? normalizeSenderUpper(libelleExpediteur) : null;
    const cleanedSignature = typeof signature === 'string' ? signature.trim().slice(0, 200) : null;

    const result = await withJsonbinUpdate(async ({ list }) => {
      const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
      if (idx === -1 || !licence) return { __skipSave: true, status: 404 };

      let changed = false;
      if (cleanedSender && cleanedSender.length >= 3) {
        licence.libelleExpediteur = cleanedSender;
        licence.expediteur = cleanedSender; // compat ancien schéma
        changed = true;
      }
      if (typeof cleanedSignature === 'string') {
        licence.signature = cleanedSignature;
        changed = true;
      }
      if (!changed) return { __skipSave: true };

      licence.updatedAt = new Date().toISOString();
      list[idx] = licence;
      return { licence };
    });

    if (result?.status === 404) return res.status(404).json({ ok:false, error:'LICENCE_INTROUVABLE' });
    return res.json({ ok:true });
  } catch (e) {
    console.error('❌ /api/licence/bootstrap', e);
    return res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// =======================
//   CGV status / accept
// =======================
app.get('/licence/cgv-status', async (req, res) => {
  try {
    const { licenceId } = req.query || {};
    if (!licenceId) return res.status(400).json({ error: 'licenceId requis' });

    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(
      list,
      l => String(l.licence) === String(licenceId) || String(l.id) === String(licenceId)
    );
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    const accepted = !!licence.cgv && licence.cgv.version === CGV_VERSION && !!licence.cgv.acceptedAt;
    const scheme = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0];
    const base = process.env.PUBLIC_SERVER_BASE || `${scheme}://${req.get('host')}`;
    const absoluteUrl = `${base}/legal/cgv-${CGV_VERSION}.md`;

    res.json({
      licenceId,
      currentVersion: CGV_VERSION,
      accepted,
      acceptedVersion: licence.cgv?.version || null,
      acceptedAt: licence.cgv?.acceptedAt || null,
      textUrl: absoluteUrl,
      serverTextHash: CGV_TEXT_HASH || null
    });
  } catch (e) {
    console.error('❌ /licence/cgv-status', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/licence/cgv-accept', async (req, res) => {
  try {
    const { licenceId, version, textHash } = req.body || {};
    if (!licenceId || !version || !textHash) {
      return res.status(400).json({ error: 'licenceId, version et textHash requis' });
    }
    if (version !== CGV_VERSION) {
      return res.status(409).json({ error: 'VERSION_MISMATCH', currentVersion: CGV_VERSION });
    }
    if (CGV_TEXT_HASH && textHash !== CGV_TEXT_HASH) {
      return res.status(409).json({ error: 'TEXT_MISMATCH' });
    }

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(
      list,
      l => String(l.licence) === String(licenceId) || String(l.id) === String(licenceId)
    );
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    const ua = req.get('user-agent') || '';
    const ip = (req.headers['x-forwarded-for']?.toString().split(',')[0] || req.ip || '').trim();
    const now = new Date().toISOString();

    licence.cgv = {
      accepted: true,
      version: CGV_VERSION,
      acceptedAt: now,
      ip,
      userAgent: ua,
      textHash,
      textUrl: `/legal/cgv-${CGV_VERSION}.md`,
      method: 'modal_click',
      locale: 'fr-FR'
    };

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    console.log('AUDIT CGV_ACCEPT', { licenceId, version: CGV_VERSION, ip, ua, at: now });
    res.json({ ok: true, acceptedAt: now, version: CGV_VERSION });
  } catch (e) {
    console.error('❌ /licence/cgv-accept', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// =======================
//   SMS helpers
// =======================
function normalizeSender(raw = 'OptiCOM') {
  let s = String(raw).replace(/[^a-zA-Z0-9]/g, '');
  if (s.length < 3) s = 'OptiCOM';
  if (s.length > 11) s = s.slice(0, 11);
  return s;
}
function normalizeTextForCompare(s = '') {
  return String(s)
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[\s\-–—_*|·•.,;:!?"'`~()]+/g, '')
    .toLowerCase();
}
function hasSignature(message = '', signature = '') {
  if (!signature) return true;
  const m = normalizeTextForCompare(message);
  const sig = normalizeTextForCompare(signature);
  return sig.length > 0 && m.includes(sig);
}
function appendSignature(message = '', signature = '') {
  if (!signature) return (message || '').trim();
  const trimmed = (message || '').trim();
  return trimmed.length ? `${trimmed}\n${signature}` : signature;
}
function buildFinalMessage(rawMessage = '', signature = '') {
  if (!signature) return (rawMessage || '').trim();
  return hasSignature(rawMessage, signature) ? (rawMessage || '').trim() : appendSignature(rawMessage, signature);
}
function toFRNumber(raw = '') {
  return String(raw).replace(/[^\d+]/g, '').replace(/^0/, '+33');
}
function ensureStopMention(text = '') {
  return /stop\s+au\s+36111/i.test(String(text)) ? String(text) : `${String(text)}\nSTOP au 36111`;
}

// Middleware — prépare sender/signature + licence JSONBin
async function applySenderAndSignature(req, res, next) {
  try {
    const { licenceId, opticienId } = req.body || {};
    const { list, rawRecord } = await jsonbinGetAll();

    const { idx, licence } = findLicenceIndex(
      list,
      (l) =>
        (licenceId && String(l.id) === String(licenceId)) ||
        (opticienId && String(l.opticien?.id) === String(opticienId))
    );

    const savedSender = (licence?.libelleExpediteur || licence?.opticien?.enseigne || 'OptiCOM').trim();
    const savedSignature = (licence?.signature || '').trim();

    req._jsonbin = { list, rawRecord, idx, licence };
    req.smsContext = { licence, idx, sender: normalizeSender(savedSender), signature: savedSignature };
    next();
  } catch (e) {
    console.error('applySenderAndSignature error:', e);
    res.status(500).json({ success: false, error: 'SERVER_SIGNATURE_SENDER_MIDDLEWARE_FAILED' });
  }
}

// ===============================
//   GoCardless: mandat & licence
// ===============================
app.post('/create-mandat', async (req, res) => {
  const {
    nomMagasin, email, adresse, ville, codePostal, pays,
    formuleId, siret, telephone,
    // 👇 ajoutés : saisis sur LicenceCheckPage
    libelleExpediteur: libelleFromClient,
    signature: signatureFromClient
  } = req.body;

  const enseigne = (nomMagasin || req.body.enseigne || req.body.nom || '').trim();
  if (!enseigne) {
    return res.status(400).json({ error: 'Le nom du magasin (enseigne) est obligatoire.' });
  }

  try {
    const session_token = uuidv4();

    const customerData = {
      email,
      company_name: enseigne,
      address_line1: adresse,
      city: ville,
      postal_code: codePostal,
      country_code: (pays || 'FR')
    };

    const response = await fetch(`${GO_CARDLESS_API_BASE}/redirect_flows`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify({
        redirect_flows: {
          description: `Abonnement ${formuleId} - OptiCOM`,
          session_token,
          success_redirect_url: `https://opticom-sms-server.onrender.com/validation-mandat?session_token=${session_token}`,
          prefilled_customer: customerData,
          metadata: { formuleId, siret, enseigne }
        }
      })
    });

    const data = await response.json();
    if (!response.ok || !data.redirect_flows?.redirect_url) {
      console.error('❌ Erreur GoCardless :', data.error);
      return res.status(500).json({ error: 'Erreur GoCardless. Vérifiez vos informations.' });
    }

    // ✅ on mémorise aussi expéditeur + signature pour l’étape /validation-mandat
    sessionTokenMap.set(session_token, {
      enseigne, email, adresse, ville, codePostal, pays, formuleId, siret, telephone,
      libelleFromClient: libelleFromClient || '', // brut
      signatureFromClient: typeof signatureFromClient === 'string' ? signatureFromClient : ''
    });

    res.status(200).json({ url: data.redirect_flows.redirect_url });
  } catch (err) {
    console.error('❗ Exception GoCardless:', err);
    res.status(500).json({ error: 'Erreur serveur GoCardless. Veuillez réessayer.' });
  }
});

async function saveLicenceDirectToJsonBin(newLicence) {
  const binId = must(JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const apiKey = must(JSONBIN_KEY, 'JSONBIN_KEY');

  const getResponse = await axios.get(`https://api.jsonbin.io/v3/b/${binId}/latest`, {
    headers: { 'X-Master-Key': apiKey, 'X-Bin-Meta': 'false' }
  });

  const record = getResponse.data?.record ?? getResponse.data;
  const list   = Array.isArray(record) ? record : (record ? [record] : []);

  const exists = list.some(l =>
    String(l.licence || '').trim().toUpperCase() === String(newLicence.licence).trim().toUpperCase() ||
    String(l.mandateId || '') === String(newLicence.mandateId) ||
    String(l.customerId || '') === String(newLicence.customerId)
  );
  if (!exists) list.push(newLicence);

  await axios.put(`https://api.jsonbin.io/v3/b/${binId}`, list, {
    headers: {
      'Content-Type': 'application/json',
      'X-Master-Key': apiKey,
      'X-Bin-Versioning': 'false'
    }
  });
}



app.get('/validation-mandat', async (req, res) => {
  const redirectFlowId = req.query.redirect_flow_id;
  const sessionToken   = req.query.session_token;
  if (!redirectFlowId || !sessionToken) {
    return res.status(400).send('Paramètre manquant ou session expirée.');
  }

  try {
    const confirmResponse = await goCardlessClient.redirectFlows.complete(
      redirectFlowId,
      { session_token: sessionToken }
    );

    // ✅ Supporte les deux formes { redirect_flows: {...} } ou {...}
    const flowObj = confirmResponse?.redirect_flows || confirmResponse;
    if (!flowObj || !flowObj.links || !flowObj.links.customer) {
      console.error('❌ Erreur GoCardless : réponse invalide', confirmResponse);
      return res.status(500).send('Erreur GoCardless : réponse invalide lors de la confirmation.');
    }

    const customerId = flowObj.links.customer;
    const mandateId  = flowObj.links.mandate;

    const opt = sessionTokenMap.get(sessionToken);
    if (!opt) return res.status(400).send('Données opticien manquantes ou session expirée.');

    const enseigne = opt.nomMagasin || opt.enseigne || 'Opticien sans nom';
    const selectedFormule = formulas.find(f => f.id === opt.formuleId) || { name: 'Formule inconnue', credits: 0 };
    const abonnement = selectedFormule.name;
    const credits    = selectedFormule.credits;

    const licenceKey = uuidv4();

    // ✅ on honore la saisie client, sinon fallback sur l’enseigne normalisée
    const libelleExpediteur =
      (opt.libelleFromClient && normalizeSenderUpper(opt.libelleFromClient)) ||
      normalizeSenderUpper(enseigne);

    const signatureClean =
      typeof opt.signatureFromClient === 'string'
        ? opt.signatureFromClient.trim().slice(0, 200)
        : '';

    const newLicence = {
      id: uuidv4(),
      licence: licenceKey,
      dateCreation: new Date().toISOString(),
      abonnement,
      credits,
      libelleExpediteur,
      signature: signatureClean,
      opticien: {
        id: 'opt-' + Math.random().toString(36).slice(2, 10),
        enseigne,
        nom: enseigne,
        email: opt.email,
        adresse: opt.adresse,
        ville: opt.ville,
        codePostal: opt.codePostal,
        pays: opt.pays,
        telephone: opt.telephone,
        siret: opt.siret
      },
      mandateId,
      customerId
    };

    // ✅ Sauvegarde JSONBin (array) – anti-doublon + fallback direct
try {
  await withJsonbinUpdate(async ({ list }) => {
    const exists = list.some(l =>
      String(l.licence || '').trim().toUpperCase() === String(licenceKey).trim().toUpperCase() ||
      String(l.mandateId || '') === String(mandateId) ||
      String(l.customerId || '') === String(customerId)
    );
    if (!exists) list.push(newLicence);
    return {};
  });
} catch (e) {
  console.warn('withJsonbinUpdate KO, fallback direct JSONBin…', e?.message || e);
  try {
    await saveLicenceDirectToJsonBin(newLicence);
  } catch (e2) {
    console.error('❌ Échec sauvegarde JSONBin (fallback):', e2);
    // on continue quand même pour afficher la page
  }
}


    sessionTokenMap.delete(sessionToken);

    if (req.headers.accept?.includes('application/json')) {
      return res.json(newLicence);
    }

    const APP_URL = (process.env.PUBLIC_APP_URL || process.env.PUBLIC_WEB_APP_URL || '').trim();
const appBase = APP_URL.replace(/\/+$/, '');

// 🔁 redirige SANS clé vers LicenceCheckPage (web ou schéma natif)
const webDeeplink    = appBase ? `${appBase}/LicenceCheckPage` : '';
const schemeDeeplink = `opticom://LicenceCheckPage`;


    res.send(`
      <html>
        <head>
          <title>Licence validée</title>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
          <style>
            :root { color-scheme: light dark; }
            body { font-family: system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; padding: 24px; background: #0b0b0b; color: #fff; }
            .box { background: #141414; border-radius: 14px; padding: 20px; max-width: 680px; margin: 0 auto; border: 1px solid #2a2a2a; }
            h1 { color: #2e7d32; margin: 0 0 10px; font-size: 22px; }
            .hint { color: #aaa; font-size: 14px; margin: 0 0 10px; }
            .row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
            code { background: #1e1e1e; border: 1px solid #333; padding: 8px 12px; font-size: 16px; border-radius: 8px; }
            .btn { display:inline-block; padding: 10px 14px; border-radius: 10px; text-decoration: none; border: 0; cursor: pointer; font-weight: 600; }
            .btn-copy { background:#2e7d32; color:#fff; }
            .btn-copy:hover { filter: brightness(1.05); }
            .btn-return { background:#1E90FF; color:#fff; margin: 14px auto 0; display:block; text-align:center; width:max-content; }
            .small { font-size: 13px; color:#9aa; margin-top:6px; text-align:center; }
          </style>
        </head>
        <body>
          <div class="box">
            <h1>🎉 Mandat validé</h1>
            <p class="hint">Voici votre clé de licence :</p>
            <div class="row">
              <code id="licenceKey">${licenceKey}</code>
              <button class="btn btn-copy" onclick="copyLicence()">📋 Copier</button>
            </div>

            <p class="small" id="autoMsg">La clé a été copiée. Redirection automatique dans <span id="sec">10</span>&nbsp;s…</p>

            <a id="returnBtn" class="btn btn-return" href="${webDeeplink || schemeDeeplink}">
              ↩️ Retourner dans l’application
            </a>
          </div>

          <script>
            async function copyLicence() {
              try {
                const txt = document.getElementById('licenceKey').textContent;
                await navigator.clipboard.writeText(txt);
                alert('Clé copiée !');
              } catch (e) {
                alert('Impossible de copier la clé : ' + e);
              }
            }

            (async function init() {
              try {
                const txt = document.getElementById('licenceKey').textContent;
                await navigator.clipboard.writeText(txt);
              } catch (e) {}

              var s = 10;
              var el = document.getElementById('sec');
              var timer = setInterval(function(){
                s--; if (el) el.textContent = String(s);
                if (s <= 0) { clearInterval(timer); go(); }
              }, 1000);

              function go(){
                var target = ${JSON.stringify(webDeeplink || '')} || ${JSON.stringify(schemeDeeplink)};
                window.location.href = target;
              }
            })();
          </script>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Erreur validation mandat :', error?.error || error);
    res.status(500).send('Erreur lors de la validation du mandat.');
  }
});

// ==== Helpers SMS & conformité ====
const crypto = require('crypto');

const lastSent = new Map();
const MIN_INTERVAL_MS = 15 * 1000;

function ymKey(d = new Date()) { return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`; }
function sha256Hex(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function normalizeFR(msisdn='') { return toFRNumber(msisdn).replace(/\D/g,''); }
function isQuietHours(date = new Date()) {
  const paris = new Date(date.toLocaleString('en-US', { timeZone: 'Europe/Paris' }));
  const day = paris.getDay();
  const hour = paris.getHours();
  return (day === 0) || (hour < 8) || (hour >= 20);
}
function hasMarketingConsent(licence) {
  const c = licence?.consentements?.marketingSms || licence?.marketingSms;
  return !!(c && c.value && !c.unsubscribedAt);
}
function isOptedOut(licence, numeroE164) {
  const n = normalizeFR(numeroE164);
  if (Array.isArray(licence?.optOuts) && licence.optOuts.some(x => normalizeFR(x) === n)) return true;
  const c = licence?.consentements?.marketingSms;
  if (c && c.unsubscribedAt) return true;
  return false;
}
function hmacShort(input='') { return crypto.createHash('sha256').update(String(input)).digest('hex').slice(0,16); }
function buildUnsubLink(licenceId, phoneE164) {
  const token = hmacShort(`${licenceId}:${phoneE164}`);
  const base = process.env.PUBLIC_SERVER_BASE || 'https://opticom-sms-server.onrender.com';
  return `${base}/unsubscribe?l=${encodeURIComponent(licenceId)}&n=${encodeURIComponent(phoneE164)}&t=${token}`;
}
async function markOptOut(licenceId, phoneE164) {
  const { list, rawRecord } = await jsonbinGetAll();
  const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
  if (idx === -1) return false;
  const set = new Set([...(licence.optOuts || [])]);
  set.add(toFRNumber(phoneE164));
  list[idx].optOuts = Array.from(set);
  await jsonbinPutAll(Array.isArray(rawRecord) ? list : list[idx]);
  return true;
}
async function appendSmsLogAndPersist({ list, rawRecord, idx, licence, entry }) {
  // Assure un id sur l'entrée
  if (!entry.id) entry.id = uuidv4();

  // Ne ré-ajoute pas un item supprimé
  const tomb = new Set(licence.smsHistoryTombstones || []);
  if (tomb.has(String(entry.id)) || (entry.textHash && tomb.has(String(entry.textHash)))) return;

  licence.historiqueSms = Array.isArray(licence.historiqueSms) ? licence.historiqueSms : [];
  licence.historiqueSms.push(entry);

  const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
  await jsonbinPutAll(bodyToPut);
}

// =======================
//  SMS History – purge
// =======================

// Handler commun
async function purgeSmsHistory({ licenceId, all, numero, phoneNumber }) {
  if (!licenceId) return { ok:false, status:400, error:'licenceId requis' };

  const num = toFRNumber(numero || phoneNumber || '');
  const { list, rawRecord } = await jsonbinGetAll();
  const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
  if (idx === -1) return { ok:false, status:404, error:'LICENCE_INTROUVABLE' };

  const before = Array.isArray(licence.historiqueSms) ? licence.historiqueSms : [];
  let after;

  if (all === true) {
    after = [];
  } else if (num) {
    const n = normalizeFR(num);
    after = before.filter(h => normalizeFR(h.numero || '') !== n);
  } else {
    return { ok:false, status:400, error:'Précisez all:true ou numero' };
  }

  const removed = before.length - after.length;
  licence.historiqueSms = after;
  licence.updatedAt = new Date().toISOString();

  const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
  await jsonbinPutAll(bodyToPut);

  return { ok:true, removed };
}

// Purge TOTALE
app.post(['/api/sms-history/erase', '/licence/history/erase'], async (req, res) => {
  try {
    const result = await purgeSmsHistory(req.body || {});
    if (result.ok) return res.json(result);
    return res.status(result.status || 400).json(result);
  } catch (e) {
    console.error('❌ purge historique (all):', e);
    return res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// Purge pour UN NUMÉRO
app.post(
  ['/api/sms-history/erase-for-number', '/licence/history/erase-for-number'],
  async (req, res) => {
    try {
      const payload = { ...(req.body || {}), all: false };
      const result = await purgeSmsHistory(payload);
      if (result.ok) return res.json(result);
      return res.status(result.status || 400).json(result);
    } catch (e) {
      console.error('❌ purge historique (num):', e);
      return res.status(500).json({ ok:false, error:'SERVER_ERROR' });
    }
  }
);

// --- Opt-out
app.get('/unsubscribe', async (req, res) => {
  try {
    const licenceId = String(req.query.l || '');
    const phone = toFRNumber(String(req.query.n || ''));
    const token = String(req.query.t || '');
    if (!licenceId || !phone || !token || token !== hmacShort(`${licenceId}:${phone}`)) {
      return res.status(400).send('Lien invalide.');
    }
    const ok = await markOptOut(licenceId, phone);
    if (!ok) return res.status(404).send('Licence introuvable.');
    res.send(`
      <html><meta charset="utf-8" />
        <body style="font-family:sans-serif;padding:30px">
          <h2>Vous êtes désinscrit des SMS marketing.</h2>
          <p>Vous ne recevrez plus de messages promotionnels de cet expéditeur.</p>
        </body>
      </html>
    `);
  } catch(e) {
    console.error('unsubscribe error', e);
    res.status(500).send('Erreur serveur.');
  }
});

// --- Admin Opt-out
app.get('/api/optouts/export', requireAdminToken, async (req, res) => {
  try {
    const { licenceId } = req.query || {};
    if (!licenceId) return res.status(400).send('licenceId requis');

    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1) return res.status(404).send('Licence introuvable');

    const items = Array.isArray(licence.optOuts) ? licence.optOuts : [];
    const csv = ['phone_e164'].concat(items).join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="optouts-${licenceId}.csv"`);
    res.send(csv);
  } catch (e) {
    console.error('export optouts error', e);
    res.status(500).send('SERVER_ERROR');
  }
});

app.post('/api/optouts/add', requireAdminToken, async (req, res) => {
  try {
    const { licenceId, phoneNumber } = req.body || {};
    if (!licenceId || !phoneNumber) {
      return res.status(400).json({ ok:false, error:'PARAMS' });
    }

    const phone = toFRNumber(phoneNumber);
    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1) return res.status(404).json({ ok:false, error:'NOT_FOUND' });

    const set = new Set([ ...(licence.optOuts || []) ]);
    set.add(phone);
    licence.optOuts = Array.from(set);

    await jsonbinPutAll(Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence);
    res.json({ ok:true });
  } catch (e) {
    console.error('optouts add error', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// =======================
//   Consentement marketing
// =======================
app.post('/consent', async (req, res) => {
  try {
    const { licenceId, phoneNumber, source = 'app' } = req.body || {};
    if (!licenceId || !phoneNumber) {
      return res.status(400).json({ success:false, error:'LICENCE_ID_ET_NUMERO_REQUIS' });
    }
    const phone = toFRNumber(phoneNumber);
    const hash = sha256Hex(phone);

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1) return res.status(404).json({ success:false, error:'LICENCE_INTROUVABLE' });

    const set = new Set([ ...(licence.consents || []) ]);
    set.add(phone);
    licence.consents = Array.from(set);

    const log = Array.isArray(licence.consentsLog) ? licence.consentsLog : [];
    log.push({
      at: new Date().toISOString(),
      phone,
      hash,
      source,
      ip: (req.headers['x-forwarded-for']?.toString().split(',')[0] || req.ip || '').trim(),
      userAgent: req.get('user-agent') || ''
    });
    licence.consentsLog = log.slice(-5000);

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ success:true });
  } catch (e) {
    console.error('❌ /consent error:', e);
    return res.status(500).json({ success:false, error:'SERVER_ERROR' });
  }
});

// ============================
//   Envoi SMS (transactionnel / promo)
// ============================
// --- Catégorie libre pour l'historique ----------------------------
function sanitizeCategorie(raw) {
  const s = String(raw || '').trim();
  return s ? s.slice(0, 32) : 'autre'; // ex: "lunettes", "lentilles", "sav", "noel", "été"
}

// ============================
//   Envoi SMS (avec catégorie)
// ============================
/** --------- Helpers de normalisation --------- **/
function toE164FR(raw) {
  // autorise "06...", "+33...", "33...", "0033..."
  let s = String(raw || '').trim();
  s = s.replace(/[^\d+]/g, '');

  // 00 -> +
  if (s.startsWith('00')) s = '+' + s.slice(2);

  // 33 sans '+' -> +33
  if (/^33\d{9}$/.test(s)) s = '+' + s;

  // 06XXXXXXXX -> +336XXXXXXXX
  const mNat = s.match(/^0(\d{9})$/);
  if (mNat) return '+33' + mNat[1];

  // +33X......... -> standardise sans 0 après 33
  if (s.startsWith('+33')) {
    // enlève un éventuel 0 juste après +33
    s = '+33' + s.slice(3).replace(/^0/, '');
  }

  return s;
}

/** Clé de rate-limit : licence + numéro FR "clé" (on enlève tout sauf chiffres) */
function rateLimitKey(licenceId, e164) {
  const digits = String(e164 || '').replace(/[^\d]/g, ''); // ex: +336... -> 336...
  return `${licenceId}:${digits}`;
}

/** Récupération du champ catégorie peu importe son nom côté client */
function pickCategory(body) {
  return sanitizeCategorie(
    body?.categorie ?? body?.category ?? body?.type ?? null
  );
}

/** --------- Transactionnel --------- **/
async function sendSmsTransactional(req, res) {
  const { phoneNumber, message, licenceId, opticienId } = req.body || {};
  if (!phoneNumber || !message || (!licenceId && !opticienId)) {
    return res.status(400).json({ success: false, error: 'Champs manquants.' });
  }
  if (!process.env.SMSMODE_LOGIN || !process.env.SMSMODE_PASSWORD) {
    return res
      .status(500)
      .json({ success: false, error: 'SMSMODE_LOGIN / SMSMODE_PASSWORD manquants.' });
  }

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    const found = licenceId
      ? findLicenceIndex(list, (l) => String(l.id) === String(licenceId))
      : findLicenceIndex(list, (l) => String(l.opticien?.id) === String(opticienId));

    if (found.idx === -1) {
      return res.status(403).json({ success: false, error: 'Licence introuvable.' });
    }
    const licence = found.licence;

    // Crédit requis si pas "Illimitée"
    if (licence.abonnement !== 'Illimitée') {
      const credits = Number(licence.credits || 0);
      if (!Number.isFinite(credits) || credits < 1) {
        return res.status(403).json({ success: false, error: 'Crédits insuffisants.' });
      }
    }

    const numeroE164 = toE164FR(phoneNumber);

    // Rate-limit par licence + numéro normalisé (E.164)
    const rlKey = rateLimitKey(licence.id, numeroE164);
    const last = lastSent.get(rlKey) || 0;
    if (Date.now() - last < MIN_INTERVAL_MS) {
      return res
        .status(429)
        .json({ success: false, error: 'Trop rapproché, réessayez dans quelques secondes.' });
    }
    lastSent.set(rlKey, Date.now());

    // Expéditeur / signature injectés par le middleware
    const { sender, signature } = req.smsContext || {};
    const finalMessage = buildFinalMessage(String(message || ''), signature || '');
    if (!finalMessage.trim()) {
      return res.status(400).json({ success: false, error: 'Message vide.' });
    }

    // Envoi SMSMode
    const params = new URLSearchParams();
    params.append('pseudo', process.env.SMSMODE_LOGIN);
    params.append('pass', process.env.SMSMODE_PASSWORD);
    params.append('message', finalMessage);
    params.append('unicode', '1');
    params.append('charset', 'UTF-8');
    params.append('smslong', '1');
    params.append('numero', numeroE164);       // ✅ on envoie E.164
    params.append('emetteur', sender || 'OPTICOM');

    const smsResp = await fetch('https://api.smsmode.com/http/1.6/sendSMS.do', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: params.toString(),
    });
    const smsText = await smsResp.text();

    const smsHasError =
      !smsResp.ok || /^32\s*\|/i.test(smsText) || /^35\s*\|/i.test(smsText) || /\berror\b/i.test(smsText);
    if (smsHasError) {
      return res.status(502).json({ success: false, error: `Erreur SMSMode: ${smsText}` });
    }

    // Décrément crédit après succès (si pas illimitée)
    if (licence.abonnement !== 'Illimitée') {
      licence.credits = Math.max(0, Number(licence.credits || 0) - 1);
    }

    // Log avec catégorie (peu importe le nom reçu)
    const categorie = pickCategory(req.body);
    await appendSmsLogAndPersist({
      list,
      rawRecord,
      idx: found.idx,
      licence,
      entry: {
        date: new Date().toISOString(),
        type: categorie,                 // ex. 'Lunettes', 'Lentilles', 'SAV', 'Commande', 'Noël', etc.
        numero: numeroE164,
        emetteur: sender,
        textHash: sha256Hex(finalMessage),
        provider: 'smsmode',
        bytes: Buffer.byteLength(finalMessage, 'utf8'),
        mois: ymKey(new Date()),
      },
    });

    return res.json({
      success: true,
      licenceId: licence.id,
      credits: licence.credits,
      abonnement: licence.abonnement,
      sender,
      message: finalMessage,
      categorie,
    });
  } catch (err) {
    console.error('Erreur /send-sms:', err);
    res.status(500).json({ success: false, error: String(err.message || err) });
  }
}

app.post('/send-sms', applySenderAndSignature, sendSmsTransactional);
app.post('/send-transactional', applySenderAndSignature, sendSmsTransactional);

/** --------- Promotionnel (marketing) --------- **/
app.post('/send-promotional', applySenderAndSignature, async (req, res) => {
  const { phoneNumber, message, licenceId, opticienId, marketingConsent } = req.body || {};

  if (!phoneNumber || (!licenceId && !opticienId)) {
    return res.status(400).json({ success: false, error: 'Champs manquants.' });
  }
  if (isQuietHours(new Date())) {
    return res.status(403).json({ success: false, error: 'ENVOI_INTERDIT_HORAIRES' });
  }

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    const found = licenceId
      ? findLicenceIndex(list, (l) => String(l.id) === String(licenceId))
      : findLicenceIndex(list, (l) => String(l.opticien?.id) === String(opticienId));

    if (found.idx === -1) {
      return res.status(403).json({ success: false, error: 'Licence introuvable.' });
    }
    const licence = found.licence;

    const numeroE164 = toE164FR(phoneNumber);

    // Consentement marketing requis (licence, global ou explicite dans la requête)
    const hasConsent =
      marketingConsent === true ||
      (Array.isArray(licence.consents) && licence.consents.includes(numeroE164)) ||
      licence.marketingConsentGlobal === true;

    if (!hasConsent) {
      return res.status(403).json({ success: false, error: 'CONSENTEMENT_MARKETING_ABSENT' });
    }

    // Opt-out vérifié
    if (isOptedOut(licence, numeroE164)) {
      return res.status(403).json({ success: false, error: 'DESTINATAIRE_DESINSCRIT' });
    }

    // Rate-limit
    const rlKey = rateLimitKey(licence.id, numeroE164);
    const last = lastSent.get(rlKey) || 0;
    if (Date.now() - last < MIN_INTERVAL_MS) {
      return res
        .status(429)
        .json({ success: false, error: 'Trop rapproché, réessayez dans quelques secondes.' });
    }
    lastSent.set(rlKey, Date.now());

    const { sender, signature } = req.smsContext || {};
    const baseText = buildFinalMessage(String(message || ''), signature || '');
    const finalMessage = ensureStopMention(baseText); // “STOP au 36111”
    if (!finalMessage.trim()) {
      return res.status(400).json({ success: false, error: 'Message vide.' });
    }

    // Envoi SMSMode
    const params = new URLSearchParams();
    params.append('pseudo', process.env.SMSMODE_LOGIN);
    params.append('pass', process.env.SMSMODE_PASSWORD);
    params.append('message', finalMessage);
    params.append('unicode', '1');
    params.append('charset', 'UTF-8');
    params.append('smslong', '1');
    params.append('numero', numeroE164);      // ✅ E.164
    params.append('emetteur', sender || 'OPTICOM');

    const smsResp = await fetch('https://api.smsmode.com/http/1.6/sendSMS.do', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: params.toString(),
    });
    const smsText = await smsResp.text();

    const smsHasError =
      !smsResp.ok || /^32\s*\|/i.test(smsText) || /^35\s*\|/i.test(smsText) || /\berror\b/i.test(smsText);
    if (smsHasError) {
      return res.status(502).json({ success: false, error: `Erreur SMSMode: ${smsText}` });
    }

    // Décrément crédit après succès
    if (licence.abonnement !== 'Illimitée') {
      licence.credits = Math.max(0, Number(licence.credits || 0) - 1);
    }

    // Log catégorie
    const categorie = pickCategory(req.body);
    await appendSmsLogAndPersist({
      list,
      rawRecord,
      idx: found.idx,
      licence,
      entry: {
        date: new Date().toISOString(),
        type: categorie,
        numero: numeroE164,
        emetteur: sender,
        textHash: sha256Hex(finalMessage),
        provider: 'smsmode',
        bytes: Buffer.byteLength(finalMessage, 'utf8'),
        mois: ymKey(new Date()),
      },
    });

    return res.json({
      success: true,
      licenceId: licence.id,
      sender,
      message: finalMessage,
      credits: licence.credits,
      categorie,
    });
  } catch (err) {
    console.error('Erreur /send-promotional:', err);
    res.status(500).json({ success: false, error: String(err.message || err) });
  }
});

// --- Historique SMS : suppression d'éléments ciblés
app.post('/api/sms/history/delete', async (req, res) => {
  try {
    const { licenceId, ids = [], textHashes = [] } = req.body || {};
    if (!licenceId) return res.status(400).json({ ok:false, error:'PARAMS' });

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1 || !licence) return res.status(404).json({ ok:false, error:'LICENCE_INTROUVABLE' });

    const before = Array.isArray(licence.historiqueSms) ? licence.historiqueSms : [];
    const idSet = new Set((ids || []).map(String));
    const thSet = new Set((textHashes || []).map(String));

    const tomb = new Set(licence.smsHistoryTombstones || []);
    for (const it of before) {
      if ((it.id && idSet.has(String(it.id))) || (it.textHash && thSet.has(String(it.textHash)))) {
        tomb.add(String(it.id || it.textHash));
      }
    }
    licence.smsHistoryTombstones = Array.from(tomb);

    const after = before.filter(it => !tomb.has(String(it.id || it.textHash)));
    licence.historiqueSms = after;
    licence.updatedAt = new Date().toISOString();

    await jsonbinPutAll(Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence);
    res.json({ ok:true, removed: before.length - after.length, total: after.length });
  } catch (e) {
    console.error('❌ /api/sms/history/delete', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// --- Historique SMS : vider entièrement
app.post('/api/sms/history/clear', async (req, res) => {
  try {
    const { licenceId } = req.body || {};
    if (!licenceId) return res.status(400).json({ ok:false, error:'PARAMS' });

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1 || !licence) return res.status(404).json({ ok:false, error:'LICENCE_INTROUVABLE' });

    const before = Array.isArray(licence.historiqueSms) ? licence.historiqueSms : [];
    const tomb = new Set(licence.smsHistoryTombstones || []);
    for (const it of before) tomb.add(String(it.id || it.textHash));
    licence.smsHistoryTombstones = Array.from(tomb);

    licence.historiqueSms = [];
    licence.updatedAt = new Date().toISOString();

    await jsonbinPutAll(Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence);
    res.json({ ok:true, removed: before.length });
  } catch (e) {
    console.error('❌ /api/sms/history/clear', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// =======================
//   SUPPORT / FEEDBACK
// =======================
const ADMIN_FEEDBACK_TOKEN = process.env.ADMIN_FEEDBACK_TOKEN || process.env.ADMIN_UPLOAD_TOKEN;

function makeInboxEntry(licence, { subject = '', message = '', email = '', platform = '', appVersion = '' }) {
  return {
    id: uuidv4(),
    date: new Date().toISOString(),
    licenceId: licence.id,
    objet: String(subject || '').slice(0, 140),
    message: String(message || '').slice(0, 4000),
    email: String(email || '').slice(0, 200),
    platform: String(platform || '').slice(0, 32),
    appVersion: String(appVersion || '').slice(0, 32),
    statut: 'nouveau'
  };
}
function collectAllFeedbackRows(list) {
  const out = [];
  for (const lic of list) {
    const inbox = Array.isArray(lic.feedbackInbox) ? lic.feedbackInbox : [];
    const legacy = Array.isArray(lic.feedbacks)
      ? lic.feedbacks.map((f) => ({
          id: f.id || uuidv4(),
          date: f.createdAt || f.date || new Date().toISOString(),
          licenceId: lic.id,
          objet: f.subject || '',
          message: f.message || '',
          email: f.email || '',
          platform: f.platform || '',
          appVersion: f.appVersion || '',
          statut: f.status === 'closed' ? 'traite' : 'nouveau'
        }))
      : [];
    for (const it of [...inbox, ...legacy]) {
      out.push({
        ...it,
        licence: lic.licence || lic.id,
        enseigne: lic.opticien?.enseigne || lic.opticien?.nom || '',
        emailLicence: lic.opticien?.email || ''
      });
    }
  }
  return out.sort((a, b) => (a.date < b.date ? 1 : -1));
}

app.post(['/support/messages', '/api/support/messages'], async (req, res) => {
  try {
    const { licenceId, subject = '', message, email = '', platform = '', appVersion = '' } = req.body || {};
    if (!licenceId || !message || !String(message).trim()) {
      return res.status(400).json({ success: false, error: 'LICENCE_ID_ET_MESSAGE_REQUIS' });
    }

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndexByAnyId(list, licenceId);
    if (idx === -1 || !licence) return res.status(404).json({ success: false, error: 'LICENCE_INTROUVABLE' });

    licence.feedbackInbox = Array.isArray(licence.feedbackInbox) ? licence.feedbackInbox : [];
    const entry = makeInboxEntry(licence, { subject, message, email, platform, appVersion });
    licence.feedbackInbox.push(entry);

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ success: true, entry });
  } catch (e) {
    console.error('❌ /support/messages (POST) error:', e);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.get(['/support/messages', '/api/support/messages'], async (req, res) => {
  try {
    const auth = req.get('authorization') || '';
    if (!ADMIN_FEEDBACK_TOKEN || auth !== `Bearer ${ADMIN_FEEDBACK_TOKEN}`) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const statusFilter = String(req.query.status || '').toLowerCase();
    const q = String(req.query.q || '').toLowerCase();

    const { list } = await jsonbinGetAll();
    let rows = collectAllFeedbackRows(list);

    if (statusFilter && statusFilter !== '*' && statusFilter !== 'tous') {
      rows = rows.filter(r => (r.statut || '').toLowerCase() === statusFilter);
    }
    if (q) {
      rows = rows.filter(r =>
        (r.objet || '').toLowerCase().includes(q) ||
        (r.message || '').toLowerCase().includes(q) ||
        (r.email || '').toLowerCase().includes(q) ||
        (r.enseigne || '').toLowerCase().includes(q) ||
        String(r.licence || '').toLowerCase().includes(q)
      );
    }
    return res.json({ items: rows, total: rows.length });
  } catch (e) {
    console.error('❌ /support/messages (GET) error:', e);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post(['/support/messages/update', '/api/support/messages/update'], async (req, res) => {
  try {
    const auth = req.get('authorization') || '';
    if (!ADMIN_FEEDBACK_TOKEN || auth !== `Bearer ${ADMIN_FEEDBACK_TOKEN}`) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const { licenceId, id, statut } = req.body || {};
    if (!licenceId || !id || !statut) return res.status(400).json({ error: 'PARAMS' });

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndexByAnyId(list, licenceId);
    if (idx === -1 || !licence) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    let changed = false;
    licence.feedbackInbox = Array.isArray(licence.feedbackInbox) ? licence.feedbackInbox : [];
    licence.feedbackInbox = licence.feedbackInbox.map((x) => {
      if (String(x.id) === String(id)) { changed = true; return { ...x, statut }; }
      return x;
    });
    if (!changed && Array.isArray(licence.feedbacks)) {
      licence.feedbacks = licence.feedbacks.map((x) => {
        if (String(x.id) === String(id)) { changed = true; return { ...x, status: (statut === 'traite' ? 'closed' : 'open') }; }
        return x;
      });
    }
    if (!changed) return res.status(404).json({ error: 'MESSAGE_INTROUVABLE' });

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ /support/messages/update error:', e);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// Compat: /feedback (legacy) → alimente aussi feedbackInbox
app.post(['/feedback', '/api/feedback'], async (req, res) => {
  try {
    const { licenceId, subject, message, email, platform, opticien } = req.body || {};
    if (!message || String(message).trim().length < 10) {
      return res.status(400).json({ ok: false, error: 'MESSAGE_TOO_SHORT' });
    }
    if (!licenceId) {
      return res.status(400).json({ ok: false, error: 'LICENCE_ID_REQUIS' });
    }

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1) return res.status(404).json({ ok: false, error: 'LICENCE_INTROUVABLE' });

    const fb = {
      id: uuidv4(),
      subject: (subject && String(subject).trim()) || 'Suggestion / Contact',
      message: String(message).trim(),
      email: (email && String(email).trim()) || '',
      platform: (platform && String(platform).trim()) || '',
      status: 'open',
      adminNotes: '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      opticien: opticien || { enseigne: licence.opticien?.enseigne || '', ville: licence.opticien?.ville || '' }
    };

    if (!Array.isArray(licence.feedbacks)) licence.feedbacks = [];
    licence.feedbacks.unshift(fb);

    // met aussi dans la boîte unifiée
    licence.feedbackInbox = Array.isArray(licence.feedbackInbox) ? licence.feedbackInbox : [];
    licence.feedbackInbox.unshift({
      id: fb.id,
      date: fb.createdAt,
      licenceId: licence.id,
      objet: fb.subject,
      message: fb.message,
      email: fb.email,
      platform: fb.platform,
      appVersion: '',
      statut: 'nouveau'
    });

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ ok: true, id: fb.id });
  } catch (e) {
    console.error('❌ POST /feedback error:', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

app.get('/api/admin/feedback', requireAdminToken, async (req, res) => {
  try {
    const { status, q, skip = '0', limit = '50' } = req.query || {};
    const { list } = await jsonbinGetAll();

    // aplatit legacy
    const out = [];
    for (const lic of list) {
      const items = Array.isArray(lic.feedbacks) ? lic.feedbacks : [];
      for (const fb of items) {
        out.push({ ...fb, licenceId: lic.id, opticien: lic.opticien || {} });
      }
    }

    let items = out;
    if (status) items = items.filter(it => it.status === status);
    if (q) {
      const rx = new RegExp(String(q), 'i');
      items = items.filter(it =>
        rx.test(it.message) || rx.test(it.subject) || rx.test(it.email) || rx.test(it.licenceId) ||
        rx.test(it.opticien?.enseigne || '')
      );
    }

    items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    const s = Math.max(0, parseInt(skip));
    const l = Math.min(200, Math.max(1, parseInt(limit)));
    const slice = items.slice(s, s + l);

    res.json({ ok: true, total: items.length, items: slice });
  } catch (e) {
    console.error('❌ GET /api/admin/feedback error:', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

app.patch('/api/admin/feedback/:id', requireAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes, handledBy } = req.body || {};

    const { list, rawRecord } = await jsonbinGetAll();
    let updated = null;

    for (let i = 0; i < list.length; i++) {
      const licence = list[i];
      const arr = Array.isArray(licence.feedbacks) ? licence.feedbacks : [];
      const j = arr.findIndex(f => f.id === id);
      if (j >= 0) {
        if (status) arr[j].status = status;
        if (typeof adminNotes === 'string') arr[j].adminNotes = adminNotes;
        if (typeof handledBy === 'string') arr[j].handledBy = handledBy;
        if (status === 'closed') arr[j].handledAt = new Date().toISOString();
        arr[j].updatedAt = new Date().toISOString();
        licence.feedbacks = arr;
        updated = { licenceId: licence.id, item: arr[j] };
        list[i] = licence;
        break;
      }
    }

    if (!updated) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    await jsonbinPutAll(Array.isArray(rawRecord) ? list : list[0] || {});
    res.json({ ok: true, ...updated });
  } catch (e) {
    console.error('❌ PATCH /api/admin/feedback/:id error:', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// Petit ping JSON brut
app.get('/api/ping', (_req, res) => res.json({ ok: true }));


// =======================
//   ADMIN : Auth licences (email & mot de passe)
// =======================

// POST /api/auth/set-password  { licenceId|cle, email, password }
app.post('/api/auth/set-password', burstLimiter, async (req, res) => {
  try {
    const { licenceId, cle, email, password } = req.body || {};
    if ((!licenceId && !cle) || !email || !password) {
      return res.status(400).json({ ok:false, error:'PARAMS' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ ok:false, error:'PASSWORD_TOO_SHORT' });
    }

    const { idx, licence, list } = await getLicenceByIdOrKey({ licenceId, cle });
    if (idx === -1 || !licence) return res.status(404).json({ ok:false, error:'LICENCE_NOT_FOUND' });

    // Empêche d’écraser un mot de passe déjà défini (sauf si tu veux autoriser du reset)
    if (licence.auth?.passHash) {
      return res.status(409).json({ ok:false, error:'PASSWORD_ALREADY_SET' });
    }

    const passHash = await bcrypt.hash(String(password), 10);
    const auth = {
      email: String(email).toLowerCase().trim(),
      passHash,
      passwordSetAt: new Date().toISOString(),
    };
    licence.auth = auth;

    const { rawRecord } = await jsonbinGetAll();
    await jsonbinPutAll(Array.isArray(rawRecord) ? (list[idx]=licence, list) : licence);

    const token = signToken({ licenceId: licence.id, email: auth.email });
    res.json({ ok:true, token, licence: { ...licence, auth:{ email: auth.email, passwordSetAt: auth.passwordSetAt } } });
  } catch (e) {
    console.error('set-password error', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// POST /api/auth/login  { (optionnel: licenceId|cle), email, password }
app.post('/api/auth/login', burstLimiter, async (req, res) => {
  try {
    const { licenceId, cle, email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok:false, error:'PARAMS' });
    }

    const emailNorm = String(email).toLowerCase().trim();

    let candidate = null;

    if (licenceId || cle) {
      // Chemin historique si on fournit encore une clé/id
      const { licence } = await getLicenceByIdOrKey({ licenceId, cle });
      candidate = licence || null;
    }

    if (!candidate) {
      // Nouveau : recherche par email seul
      const { list } = await jsonbinGetAll(true); // force dernier état
      const matches = (list || []).filter(
        (l) => l?.auth?.email && String(l.auth.email).toLowerCase() === emailNorm && l?.auth?.passHash
      );
      if (matches.length > 1) {
        // on prend la plus “récente”
        matches.sort((a,b) => new Date(b.updatedAt || b.dateCreation || 0) - new Date(a.updatedAt || a.dateCreation || 0));
      }
      candidate = matches[0] || null;
    }

    if (!candidate || !candidate.auth?.passHash) {
      return res.status(404).json({ ok:false, error:'AUTH_NOT_INITIALIZED' });
    }

    const okPass = await bcrypt.compare(String(password), String(candidate.auth.passHash));
    if (!okPass) return res.status(401).json({ ok:false, error:'BAD_CREDENTIALS' });

    const token = signToken({ licenceId: candidate.id, email: candidate.auth.email });
    return res.json({ ok:true, token, licence: candidate });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});


// GET /api/auth/me   (Authorization: Bearer <token>)
app.get('/api/auth/me', burstLimiter, async (req, res) => {
  try {
    const auth = (req.get('authorization')||'').split(' ')[1] || '';
    const decoded = verifyToken(auth);
    if (!decoded?.licenceId) return res.status(401).json({ ok:false, error:'INVALID_TOKEN' });

    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(decoded.licenceId));
    if (idx === -1 || !licence) return res.status(404).json({ ok:false, error:'LICENCE_NOT_FOUND' });

    res.json({ ok:true, licence });
  } catch (e) {
    console.error('me error', e);
    res.status(401).json({ ok:false, error:'INVALID_TOKEN' });
  }
});

// === à placer juste sous tes routes /api/auth/set-password|login|me ===

// GET /auth/has-account?licenceId=... | &cle=...
app.get(['/auth/has-account','/api/auth/has-account'], burstLimiter, async (req, res) => {
  try {
    const { licenceId, cle } = req.query || {};
    const { licence } = await getLicenceByIdOrKey({ licenceId, cle });
    if (!licence) return res.json({ accountExists: false });
    return res.json({ accountExists: !!(licence.auth && licence.auth.passHash), email: licence.auth?.email || null });
  } catch (e) {
    console.error('has-account error', e);
    return res.json({ accountExists: false });
  }
});

// POST /auth/register  { licenceId|cle, email, password }
app.post(['/auth/register','/api/auth/register'], burstLimiter, async (req, res) => {
  try {
    const { licenceId, cle, email, password } = req.body || {};
    if ((!licenceId && !cle) || !email || !password) {
      return res.status(400).json({ ok:false, error:'PARAMS' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ ok:false, error:'PASSWORD_TOO_SHORT' });
    }

    const { idx, licence, list } = await getLicenceByIdOrKey({ licenceId, cle });
    if (idx === -1 || !licence) return res.status(404).json({ ok:false, error:'LICENCE_NOT_FOUND' });
    if (licence.auth?.passHash) {
      return res.status(409).json({ ok:false, error:'PASSWORD_ALREADY_SET' });
    }

    const passHash = await bcrypt.hash(String(password), 10);
    const auth = {
      email: String(email).toLowerCase().trim(),
      passHash,
      passwordSetAt: new Date().toISOString(),
    };
    licence.auth = auth;

    const { rawRecord } = await jsonbinGetAll();
    await jsonbinPutAll(Array.isArray(rawRecord) ? (list[idx]=licence, list) : licence);

    const token = signToken({ licenceId: licence.id, email: auth.email });
    res.json({ ok:true, token, licence: { ...licence, auth:{ email: auth.email, passwordSetAt: auth.passwordSetAt } } });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});


app.post('/api/admin/auth/reset-password', requireAdminToken, async (req, res) => { /* ... */ });
app.post('/api/admin/auth/clear-password', requireAdminToken, async (req, res) => { /* ... */ });
app.post('/api/admin/auth/update-email', requireAdminToken, async (req, res) => { /* ... */ });
app.get ('/api/admin/auth/status', requireAdminToken,  async (req, res) => { /* ... */ });

// === Opti: login admin (retourne un JWT admin)
app.post('/admin/login', burstLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    return res.status(500).json({ error: 'ADMIN_CREDS_MISSING' });
  }
  const ok =
    String(email || '').toLowerCase().trim() === String(ADMIN_EMAIL).toLowerCase().trim() &&
    String(password || '') === String(ADMIN_PASSWORD);

  if (!ok) return res.status(401).json({ error: 'BAD_CREDENTIALS' });

  const token = signAdmin({ role: 'admin', email: ADMIN_EMAIL });
  res.json({ ok: true, token });
});

// (optionnel) vérifier le token admin
app.get('/admin/me', requireAdmin, (req, res) => {
  res.json({ ok: true, role: 'admin' });
});

// Tous les endpoints sous /api/admin/secure/* nécessitent le JWT admin
app.use('/api/admin/secure', requireAdmin);

// Liste complète des licences (vue OptiAdmin)
app.get('/api/admin/secure/licences', async (_req, res) => {
  try {
    const { list } = await jsonbinGetAll();
    res.json({ items: list || [] });
  } catch (e) {
    console.error('admin licences error', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// Lecture d’une licence précise
app.get('/api/admin/secure/licence/:id', async (req, res) => {
  try {
    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(req.params.id));
    if (idx === -1 || !licence) return res.status(404).json({ error: 'NOT_FOUND' });
    res.json({ licence });
  } catch (e) {
    console.error('admin licence read error', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// Patch “admin” (autorise tout, y compris champs protégés si tu le souhaites)
app.post('/api/admin/secure/licence/:id/sync', async (req, res) => {
  try {
    const { patch = {} } = req.body || {};
    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(req.params.id));
    if (idx === -1 || !licence) return res.status(404).json({ error: 'NOT_FOUND' });

    // ⚠️ Admin : merge sans strip (tu peux restreindre via une whitelist si besoin)
    const updated = { ...licence, ...patch, updatedAt: new Date().toISOString() };
    const body = Array.isArray(rawRecord) ? (list[idx] = updated, list) : updated;
    await jsonbinPutAll(body);
    res.json({ ok: true, licence: updated });
  } catch (e) {
    console.error('admin licence sync error', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// DELETE licence (admin) — supprime vraiment de JSONBin
// 1) Par ID:        DELETE /api/admin/secure/licences/:id
//                   DELETE /api/admin/secure/licence/:id    // alias
// 2) Par clé (cle): DELETE /api/admin/secure/licences?cle=XXXX
//                   DELETE /api/admin/secure/licence?cle=XXXX
app.delete(
  [
    '/api/admin/secure/licences/:id',
    '/api/admin/secure/licences',
    '/api/admin/secure/licence/:id', // alias singulier
    '/api/admin/secure/licence',     // alias singulier
  ],
  requireAdmin,
  async (req, res) => {
    try {
      const rawId = (req.params?.id || '').trim();
      const rawCle = (req.query?.cle || '').toString().trim();

      if (!rawId && !rawCle) {
        return res.status(400).json({ ok: false, error: 'PARAMS' });
      }

      const NK = (s) => String(s || '').replace(/[\s-]/g, '').toUpperCase();

      const result = await withJsonbinUpdate(async ({ list }) => {
        let idx = -1;

        if (rawId) {
          const idNK = NK(rawId);
          idx = list.findIndex((l) =>
            String(l.id) === rawId ||                     // id exact
            NK(l.licence || l.cle || l.key) === idNK ||   // clé passée dans :id
            String(l.opticien?.id) === rawId              // opticien.id
          );
        } else if (rawCle) {
          const keyNK = NK(rawCle);
          idx = list.findIndex((l) => NK(l.licence || l.cle || l.key) === keyNK);
        }

        if (idx === -1) {
          return { __skipSave: true, status: 404, error: 'LICENCE_NOT_FOUND' };
        }

        const removed = list.splice(idx, 1)[0]; // ✅ suppression réelle
        return {
          removedId:  removed?.id || null,
          removedKey: removed?.licence || removed?.cle || null,
        };
      });

      if (result?.status === 404) {
        return res.status(404).json({ ok: false, error: 'LICENCE_NOT_FOUND' });
      }
      return res.json({
        ok: true,
        removedId: result.removedId,
        removedKey: result.removedKey,
      });
    } catch (e) {
      console.error('admin delete licence error', e);
      return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
    }
  }
);


// =======================
//   Achat de crédits via GoCardless
// =======================
app.post('/achat-credits-gocardless', async (req, res) => {
  const { email, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity || '1'));

  const prixHT = 6;
  const tauxTVA = 0.20;
  const prixTTC = prixHT * (1 + tauxTVA);

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l =>
      String(l.opticien?.email).toLowerCase() === String(email).toLowerCase()
    );
    if (idx === -1) return res.status(404).json({ error: 'Licence introuvable' });

    const mandate = licence.mandateId;
    if (!mandate) return res.status(400).json({ error: 'Aucun mandat associé à cette licence' });

    const response = await fetch(`${GO_CARDLESS_API_BASE}/payments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify({
        payments: {
          amount: Math.round(prixTTC * qty * 100),
          currency: 'EUR',
          links: { mandate },
          description: `Achat ponctuel de ${qty * 100} crédits SMS - OptiCOM`,
          metadata: { email, type: 'achat-credits', quantity: String(qty) }
        }
      })
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('❗ Erreur GoCardless :', JSON.stringify(data, null, 2));
      return res.status(500).json({ error: 'Échec du paiement GoCardless.' });
    }

    const creditsAjoutes = qty * 100;
    licence.credits = (Number(licence.credits) || 0) + creditsAjoutes;
    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    try {
      const facturePayload = {
        opticien: licence.opticien,
        type: 'Achat de crédits SMS (GoCardless)',
        montantHT: prixHT * qty,
        montantTTC: prixTTC * qty,
        tva: prixHT * qty * tauxTVA,
        details: `${creditsAjoutes} crédits achetés via GoCardless`
      };

      const base = process.env.PUBLIC_SERVER_BASE || `https://opticom-sms-server.onrender.com`;
      const factureResponse = await fetch(`${base}/api/generate-invoice`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(facturePayload)
      });

      const factureData = await factureResponse.json();
      console.log('✅ Facture générée :', factureData);

      if (factureData?.url) {
        const { list: list2, rawRecord: rec2 } = await jsonbinGetAll();
        const { idx: idx2 } = findLicenceIndex(list2, l => String(l.id) === String(licence.id));
        if (idx2 !== -1) {
          if (!Array.isArray(list2[idx2].factures)) list2[idx2].factures = [];
          list2[idx2].factures.push({
            date: new Date().toISOString(),
            url: factureData.url,
            type: 'GoCardless',
            montantHT: prixHT * qty,
            montantTTC: prixTTC * qty,
            tva: prixHT * qty * tauxTVA,
            credits: creditsAjoutes
          });
          await jsonbinPutAll(Array.isArray(rec2) ? list2 : list2[idx2]);
        }
      }
    } catch (e) {
      console.error('❌ Erreur génération facture :', e);
    }

    res.json({ success: true, creditsAjoutes, prixHT, prixTTC, tva: prixHT * tauxTVA });
  } catch (err) {
    console.error('❗ Erreur achat GoCardless (serveur) :', err);
    res.status(500).json({ error: 'Erreur serveur inattendue' });
  }
});

// =======================
//   Stripe: checkout + webhook RAW
// =======================
app.post('/create-checkout-session', async (req, res) => {
  const { clientEmail, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity || '1'));

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: { name: 'Crédits SMS OptiCOM (lot de 100)' },
          unit_amount: 1700
        },
        quantity: qty
      }],
      success_url: `opticom://merci-achat?credits=${qty * 100}`,
      cancel_url: 'opticom://annulation-achat',
      metadata: { email: clientEmail || '', quantity: String(qty) }
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('❗Erreur Stripe:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la session Stripe.' });
  }
});

app.post('/webhook-stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('❌ Erreur de signature Stripe :', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.metadata?.email;
    const quantity = parseInt(session.metadata?.quantity || '1');
    if (email) {
      try {
        const { list, rawRecord } = await jsonbinGetAll();
        const { idx } = findLicenceIndex(list, l => String(l.opticien?.email).toLowerCase() === String(email).toLowerCase());
        if (idx !== -1) {
          const creditsAjoutes = 100 * quantity;
          list[idx].credits = (Number(list[idx].credits) || 0) + creditsAjoutes;

          // facture PDF
          const facturePayload = {
            opticien: list[idx].opticien,
            type: 'Achat de crédits SMS (Stripe)',
            montant: 17 * quantity, // TTC
            details: `${creditsAjoutes} crédits achetés`
          };
          let invoiceUrl = null;
          try {
            const scheme = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0];
            const base = process.env.PUBLIC_SERVER_BASE || `${scheme}://${req.get('host')}`;
            const response = await fetch(`${base}/api/generate-invoice`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(facturePayload)
            });
            const data = await response.json();
            invoiceUrl = data.url;
          } catch (e) {
            console.error('❌ Erreur génération facture Stripe :', e);
          }

          if (!Array.isArray(list[idx].factures)) list[idx].factures = [];
          if (invoiceUrl) {
            list[idx].factures.push({
              date: new Date().toISOString(),
              url: invoiceUrl,
              type: 'Stripe',
              montant: 17 * quantity,
              credits: creditsAjoutes
            });
          }

          const bodyToPut = Array.isArray(rawRecord) ? list : list[idx];
          await jsonbinPutAll(bodyToPut);
          console.log(`✅ ${creditsAjoutes} crédits ajoutés (Stripe) pour ${email}`);
        }
      } catch (e) {
        console.error('❌ Webhook Stripe JSONBin error:', e);
      }
    }
  }

  res.status(200).send('OK');
});

// =======================
//   Licences - API
// =======================
async function findLicence({ cle, id }) {
  const { list } = await jsonbinGetAll();
  if (id) {
    const byId = list.find((l) => String(l.id).toLowerCase() === String(id).toLowerCase());
    if (byId) return byId;
  }
  if (cle) {
    const q = normKey(cle);
    const byKey = list.find((l) => normKey(l.licence || l.cle || l.key || '') === q);
    if (byKey) return byKey;
  }
  return null;
}

// 👇 burst limiter sur endpoints sensibles
// Limiter seulement les lectures (GET) pour éviter de bloquer les upserts
app.use(['/api/licence', '/licence', '/api/licence/by-key', '/licence/by-key', '/licence-by-key'], burstLimiter);
// /api/clients : limiter uniquement le GET (la synchro fait un POST + GET)
app.get('/api/clients', burstLimiter);


app.get(
  ['/api/licence/by-key', '/licence/by-key', '/licence-by-key', '/api/licence', '/licence'],
  async (req, res) => {
    try {
      const cle = req.query.cle || req.query.key || req.query.k;
      const id  = req.query.id;
      if (!cle && !id) return res.status(400).json({ error: 'Paramètre cle ou id requis' });

      const licence = await findLicence({ cle, id });
      if (!licence) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

      // ⬇️ On renvoie une copie filtrée (évite de muter l’original)
      const clone = JSON.parse(JSON.stringify(licence));
      const tomb = new Set(clone.smsHistoryTombstones || []);
      if (Array.isArray(clone.historiqueSms) && tomb.size) {
        clone.historiqueSms = clone.historiqueSms.filter(
          it => !tomb.has(String(it.id || it.textHash))
        );
      }

      res.set('Cache-Control', 'public, max-age=15, stale-while-revalidate=60');
      return res.json({ licence: clone });
    } catch (e) {
      console.error('❌ /licence/by-key error:', e);
      return res.status(500).json({ error: 'SERVER_ERROR' });
    }
  }
);

app.get('/api/licences', async (_req, res) => {
  try {
    const { list } = await jsonbinGetAll();
    const items = (Array.isArray(list) ? list : (list ? [list] : []))
      .map((lic) => {
        const clone = JSON.parse(JSON.stringify(lic));
        const tomb = new Set(clone.smsHistoryTombstones || []);
        if (Array.isArray(clone.historiqueSms) && tomb.size) {
          clone.historiqueSms = clone.historiqueSms.filter(
            it => !tomb.has(String(it.id || it.textHash))
          );
        }
        return clone;
      });
    res.json(items);
  } catch (e) {
    console.error('❌ /api/licences error:', e);
    res.status(500).json({ error: 'JSONBIN_READ_FAILED', detail: String(e.message || e) });
  }
});

// Le client envoie un patch partiel { ... } — les PROTECTED_FIELDS sont conservés
app.post('/api/licence/sync-safe', async (req, res) => {
  try {
    const { licenceId, patch } = req.body || {};
    if (!licenceId || typeof patch !== 'object') {
      return res.status(400).json({ ok:false, error:'PARAMS' });
    }

    // 🔎 On récupère la licence pour connaître ses tombstones
    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    if (idx === -1 || !licence) return res.status(404).json({ ok:false, error:'LICENCE_INTROUVABLE' });

    // ⛔️ Empêche la resync d’écraser libellé/signature etc.
    const protectedKeys = new Set(['libelleExpediteur', 'signature', 'smsHistoryTombstones']);
    const safePatch = Object.fromEntries(
      Object.entries(patch).filter(([k]) => !protectedKeys.has(k))
    );

    // 🧹 Si on reçoit un historique dans le patch, on enlève les items tombstonés
    if (Array.isArray(safePatch.historiqueSms)) {
      const tomb = new Set(licence.smsHistoryTombstones || []);
      safePatch.historiqueSms = safePatch.historiqueSms.filter(
        it => !tomb.has(String(it.id || it.textHash))
      );
    }

    // 👉 updateLicenceFields (ta version avec allowKeys) préservera de toute façon les champs protégés
    const r = await updateLicenceFields({ licenceId, patch: safePatch, allowKeys: [] });
    if (!r.ok) return res.status(r.status || 500).json({ ok:false, error:r.error });

    // On renvoie aussi une licence filtrée (comme les GET)
    const clone = JSON.parse(JSON.stringify(r.licence));
    const tomb = new Set(clone.smsHistoryTombstones || []);
    if (Array.isArray(clone.historiqueSms) && tomb.size) {
      clone.historiqueSms = clone.historiqueSms.filter(
        it => !tomb.has(String(it.id || it.textHash))
      );
    }

    res.json({ ok:true, licence: clone });
  } catch (e) {
    console.error('❌ /api/licence/sync-safe', e);
    res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});

// =======================
//   Préférences auto
// =======================
app.get('/api/licence/prefs', async (req, res) => {
  try {
    const { licenceId } = req.query || {};
    if (!licenceId) return res.status(400).json({ error: 'licenceId requis' });

    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l =>
      String(l.id) === String(licenceId) || String(l.licence) === String(licenceId)
    );
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    const a = licence.automations || {};
    return res.json({
      autoBirthdayEnabled: !!a.autoBirthdayEnabled,
      autoLensRenewalEnabled: !!a.autoLensRenewalEnabled,
      lensAdvanceDays: Number.isFinite(+a.lensAdvanceDays) ? +a.lensAdvanceDays : 10,
      messageBirthday: a.messageBirthday || 'Joyeux anniversaire {prenom} !',
      messageLensRenewal: a.messageLensRenewal || 'Bonjour {prenom}, pensez au renouvellement de vos lentilles.'
    });
  } catch (e) {
    console.error('GET /api/licence/prefs', e);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/licence/prefs', async (req, res) => {
  try {
    const { licenceId, autoBirthdayEnabled, autoLensRenewalEnabled, messageBirthday, messageLensRenewal, lensAdvanceDays } = req.body || {};
    if (!licenceId) return res.status(400).json({ error: 'licenceId requis' });

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l =>
      String(l.id) === String(licenceId) || String(l.licence) === String(licenceId)
    );
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    const cleanStr = (s, def) => (typeof s === 'string' && s.trim() ? s.trim().slice(0, 300) : def);
    const lad = Number.isFinite(+lensAdvanceDays) ? Math.max(0, Math.min(60, +lensAdvanceDays)) : 10;

    licence.automations = {
      autoBirthdayEnabled: !!autoBirthdayEnabled,
      autoLensRenewalEnabled: !!autoLensRenewalEnabled,
      lensAdvanceDays: lad,
      messageBirthday: cleanStr(messageBirthday, 'Joyeux anniversaire {prenom} !'),
      messageLensRenewal: cleanStr(messageLensRenewal, 'Bonjour {prenom}, pensez au renouvellement de vos lentilles.')
    };
    licence.updatedAt = new Date().toISOString();

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ ok: true, automations: licence.automations });
  } catch (e) {
    console.error('POST /api/licence/prefs', e);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ===== Templates (messages sauvegardés par licence) =====
app.get('/api/templates', async (req, res) => {
  try {
    const { licenceId } = req.query || {};
    if (!licenceId) return res.status(400).json({ error: 'licenceId requis' });

    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId) || String(l.licence) === String(licenceId));
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    res.json({ items: Array.isArray(licence.templates) ? licence.templates : [] });
  } catch (e) {
    console.error('GET /api/templates', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/templates/save', async (req, res) => {
  try {
    const { licenceId, items } = req.body || {};
    if (!licenceId || !Array.isArray(items)) return res.status(400).json({ error: 'PARAMS' });

    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId) || String(l.licence) === String(licenceId));
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    const sanitized = items.slice(0, 200).map(t => ({
      id: t.id || uuidv4(),
      label: String(t.label || '').slice(0, 100),
      text: String(t.text || '').slice(0, 1000)
    }));

    licence.templates = sanitized;
    licence.updatedAt = new Date().toISOString();

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);
    res.json({ ok: true, items: sanitized });
  } catch (e) {
    console.error('POST /api/templates/save', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// ===== Clients (synchronisation multi-postes) =====
function cleanClient(c) {
  return {
    id: c.id || uuidv4(),
    prenom: String(c.prenom || c.firstName || '').slice(0, 80),
    nom: String(c.nom || c.lastName || '').slice(0, 80),
    phone: toFRNumber(c.phone || c.telephone || c.mobile || ''),
    email: String(c.email || '').slice(0, 160),
    naissance: c.naissance || c.birthdate || null,
    lensStartDate: c.lensStartDate || null,
    lensEndDate: c.lensEndDate || null,
    lensDuration: c.lensDuration || null,
    note: String(c.note || '').slice(0, 500),
    updatedAt: c.updatedAt || new Date().toISOString(),
    deletedAt: c.deletedAt || null
  };
}

app.get('/api/clients', async (req, res) => {
  try {
    const { licenceId } = req.query || {};
    if (!licenceId) return res.status(400).json({ error: 'licenceId requis' });

    const { list } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.id) === String(licenceId) || String(l.licence) === String(licenceId));
    if (idx === -1) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    const clients = Array.isArray(licence.clients) ? licence.clients : [];
    res.set('Cache-Control', 'public, max-age=15, stale-while-revalidate=60');
    res.json({ items: clients.filter(c => !c.deletedAt) });
  } catch (e) {
    console.error('GET /api/clients', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/clients/upsert', async (req, res) => {
  try {
    const { licenceId, clients } = req.body || {};
    if (!licenceId || !Array.isArray(clients)) return res.status(400).json({ error: 'PARAMS' });

    const result = await withJsonbinUpdate(({ list }) => {
      const { idx, licence } = findLicenceIndex(list, l =>
        String(l.id) === String(licenceId) || String(l.licence) === String(licenceId)
      );
      if (idx === -1 || !licence) return { __skipSave: true, status: 404 };

      const exists = new Map();
      const current = Array.isArray(licence.clients) ? licence.clients : [];
      for (const c of current) exists.set(String(c.id), c);

      let changed = 0;
      for (const raw of clients.slice(0, 5000)) {
        const nc = cleanClient(raw);
        const prev = exists.get(String(nc.id));
        if (!prev || new Date(nc.updatedAt) > new Date(prev.updatedAt)) {
          exists.set(String(nc.id), { ...(prev || {}), ...nc });
          changed++;
        }
      }

      const merged = Array.from(exists.values()).slice(-50000);
      list[idx] = { ...list[idx], clients: merged, updatedAt: new Date().toISOString() }; // ✅ on ne touche qu’aux clients
      return { changed, total: merged.length };
    });

    if (result?.status === 404) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });
    res.json({ ok: true, changed: result.changed, total: result.total });
  } catch (e) {
    console.error('POST /api/clients/upsert', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.delete('/api/clients/:id', async (req, res) => {
  try {
    const { licenceId } = req.query || {};
    const { id } = req.params || {};
    if (!licenceId || !id) return res.status(400).json({ error: 'PARAMS' });

    const result = await withJsonbinUpdate(({ list }) => {
      const { idx, licence } = findLicenceIndex(list, l =>
        String(l.id) === String(licenceId) || String(l.licence) === String(licenceId)
      );
      if (idx === -1 || !licence) return { __skipSave: true, status: 404 };
      const arr = Array.isArray(licence.clients) ? licence.clients : [];
      const j = arr.findIndex(c => String(c.id) === String(id));
      if (j === -1) return { __skipSave: true, status: 404, code: 'CLIENT_INTROUVABLE' };
      arr[j].deletedAt = new Date().toISOString();
      arr[j].updatedAt = arr[j].deletedAt;
      list[idx].clients = arr;
      return {};
    });

    if (result?.status === 404) {
      if (result.code === 'CLIENT_INTROUVABLE') return res.status(404).json({ error: 'CLIENT_INTROUVABLE' });
      return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /api/clients/:id', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// =======================
//   CRON formules / résiliation
// =======================
const cron = require('node-cron');
const ISO = (d = new Date()) => d.toISOString().slice(0, 10);
const TARIFS_GC = { Starter: 600, Pro: 1200, Premium: 1800 };

cron.schedule('0 3 * * *', async () => {
  console.log('⏳ CRON: vérification formules & résiliations...');
  const today = ISO();

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    let updated = false;

    for (let i = 0; i < list.length; i++) {
      const licence = list[i];

      if (licence.nouvelleFormule && licence.dateChangement) {
        if (today >= String(licence.dateChangement).slice(0, 10)) {
          const newPlan = String(licence.nouvelleFormule);
          console.log(`🔄 Passage de ${licence.opticien?.email} à la formule ${newPlan}`);

          licence.abonnement = newPlan;
          delete licence.nouvelleFormule;
          delete licence.dateChangement;
          updated = true;

          const amount = TARIFS_GC[newPlan] || TARIFS_GC.Starter;
          if (licence.subscriptionId) {
            try {
              await fetch(`${GO_CARDLESS_API_BASE}/subscriptions/${licence.subscriptionId}`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
                  'GoCardless-Version': '2015-07-06'
                },
                body: JSON.stringify({ subscriptions: { amount } })
              });
              console.log(`✅ Subscription mise à jour (${amount} centimes) pour ${licence.opticien?.email}`);
            } catch (e) {
              console.error('❌ GC update subscription amount:', e);
            }
          }
        }
      }

      const resiDate = licence.dateResiliation || licence.resiliationDate;
      if (resiDate) {
        const cut = String(resiDate).slice(0, 10);
        if (today >= cut) {
          console.log(`🛑 Résiliation effective pour ${licence.opticien?.email} (date ${cut})`);

          try {
            if (licence.subscriptionId) {
              await fetch(`${GO_CARDLESS_API_BASE}/subscriptions/${licence.subscriptionId}/actions/cancel`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
                  'GoCardless-Version': '2015-07-06'
                },
                body: JSON.stringify({})
              });
              console.log(`✅ Subscription annulée pour ${licence.opticien?.email}`);
            } else if (licence.mandateId) {
              await fetch(`${GO_CARDLESS_API_BASE}/mandates/${licence.mandateId}/actions/cancel`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
                  'GoCardless-Version': '2015-07-06'
                },
                body: JSON.stringify({})
              });
              console.log(`✅ Mandat annulé pour ${licence.opticien?.email}`);
            }
          } catch (e) {
            console.error('❌ GC cancel (subscription/mandate):', e);
          }

          licence.active = false;
          delete licence.licence;
          delete licence.credits;
          updated = true;
        }
      }
    }

    if (updated) {
      await jsonbinPutAll(Array.isArray(rawRecord) ? list : list[0] || {});
      console.log('✅ CRON: mises à jour sauvegardées.');
    } else {
      console.log('👌 CRON: rien à faire aujourd’hui.');
    }
  } catch (err) {
    console.error('❌ Erreur CRON:', err);
  }
}, { timezone: 'Europe/Paris' }); // ✅ TZ Paris

// =======================
//   Automatisations (anniv / lentilles)
// =======================
const PARIS_TZ = 'Europe/Paris';
function isoTodayParis() {
  const d = new Date(new Date().toLocaleString('en-US', { timeZone: PARIS_TZ }));
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2,'0');
  const day = String(d.getDate()).padStart(2,'0');
  return `${y}-${m}-${day}`;
}
function dateFromISO(iso) {
  const [y,m,d] = String(iso).split('-').map(Number);
  if (!y || !m || !d) return null;
  return new Date(Date.UTC(y, m-1, d, 0, 0, 0));
}
function frToISO(s) {
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(String(s).trim());
  if (!m) return null;
  const [_, dd, mm, yyyy] = m;
  return `${yyyy}-${mm}-${dd}`;
}
function parseToISODate(s) {
  if (!s) return null;
  const str = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(str)) return str;
  const fr = frToISO(str);
  return fr || null;
}
function addDaysISO(iso, days) {
  const d = dateFromISO(iso);
  if (!d) return null;
  d.setUTCDate(d.getUTCDate() + Number(days || 0));
  return d.toISOString().slice(0,10);
}
function addMonthsISO(iso, months) {
  const d = dateFromISO(iso);
  if (!d) return null;
  const y = d.getUTCFullYear();
  const m = d.getUTCMonth();
  const day = d.getUTCDate();
  const targetM = m + Number(months || 0);
  const targetY = y + Math.floor(targetM / 12);
  const targetMonth = ((targetM % 12) + 12) % 12;
  const lastDay = new Date(Date.UTC(targetY, targetMonth + 1, 0)).getUTCDate();
  d.setUTCFullYear(targetY, targetMonth, Math.min(day, lastDay));
  return d.toISOString().slice(0,10);
}
function renderTemplate(tpl, ctx) {
  return String(tpl || '')
    .replace(/\{prenom\}/gi, ctx.prenom || '')
    .replace(/\{nom\}/gi, ctx.nom || '');
}
function sameMonthDay(dateStr) {
  const iso = parseToISODate(dateStr);
  if (!iso) return false;
  const today = isoTodayParis();
  return today.slice(5) === iso.slice(5);
}
function pickClientPhone(c) { return c?.phone || c?.telephone || c?.mobile || c?.gsm || ''; }

async function sendSmsAutoForLicence({ licence, list, rawRecord, idx, numero, text, type }) {
  if (!process.env.SMSMODE_LOGIN || !process.env.SMSMODE_PASSWORD) return { ok:false, reason:'SMSMODE_ENV_MISSING' };

  const numeroE164 = toFRNumber(numero);
  const rlKey = `${licence.id}:${normalizeFR(numeroE164)}`;
  const last = lastSent.get(rlKey) || 0;
  if (Date.now() - last < MIN_INTERVAL_MS) return { ok:false, reason:'RATE_LIMIT' };
  lastSent.set(rlKey, Date.now());

  const sender = normalizeSender(licence.libelleExpediteur || licence.opticien?.enseigne || 'OptiCOM');
  const finalText = ensureStopMention(buildFinalMessage(renderTemplate(text, {}), licence.signature || ''));

  if (licence.abonnement !== 'Illimitée') {
    const credits = Number(licence.credits || 0);
    if (!Number.isFinite(credits) || credits < 1) return { ok:false, reason:'NO_CREDITS' };
  }

  const params = new URLSearchParams();
  params.append('pseudo', process.env.SMSMODE_LOGIN);
  params.append('pass', process.env.SMSMODE_PASSWORD);
  params.append('message', finalText);
  params.append('unicode', '1');
  params.append('charset', 'UTF-8');
  params.append('smslong', '1');
  params.append('numero', numeroE164);
  params.append('emetteur', sender);

  const smsResp = await fetch('https://api.smsmode.com/http/1.6/sendSMS.do', {
    method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8' }, body: params.toString()
  });
  const smsText = await smsResp.text();
  const smsHasError = !smsResp.ok || /^32\s*\|/i.test(smsText) || /^35\s*\|/i.test(smsText) || /\berror\b/i.test(smsText);
  if (smsHasError) return { ok:false, reason:`SMS_ERR:${smsText}` };

  if (licence.abonnement !== 'Illimitée') {
    licence.credits = Math.max(0, Number(licence.credits || 0) - 1);
  }
  await appendSmsLogAndPersist({
    list, rawRecord, idx, licence,
    entry: {
      date: new Date().toISOString(),
      type,
      numero: numeroE164,
      emetteur: sender,
      textHash: sha256Hex(finalText),
      provider: 'smsmode',
      bytes: Buffer.byteLength(finalText, 'utf8'),
      mois: ymKey(new Date())
    }
  });

  return { ok:true };
}

cron.schedule('15 9 * * *', async () => {
  const todayISO = isoTodayParis();
  console.log('⏳ CRON: automatisations (anniv / lentilles J-10)…', todayISO);
  try {
    const { list, rawRecord } = await jsonbinGetAll();
    let touched = false;

    for (let i = 0; i < list.length; i++) {
      const licence = list[i];
      const a = licence.automations || {};
      if (!a.autoBirthdayEnabled && !a.autoLensRenewalEnabled) continue;

      const clients = Array.isArray(licence.clients) ? licence.clients
                    : Array.isArray(licence.patients) ? licence.patients : [];
      if (!clients.length) continue;

      licence.automationLog = Array.isArray(licence.automationLog) ? licence.automationLog : [];

      // Anniversaire
      if (a.autoBirthdayEnabled) {
        const tpl = a.messageBirthday || 'Joyeux anniversaire {prenom} !';
        for (const c of clients) {
          if (!(sameMonthDay(c?.naissance) || sameMonthDay(c?.birthdate) || sameMonthDay(c?.dateNaissance))) continue;
          const phone = pickClientPhone(c);
          if (!phone) continue;
          const key = `anniv:${todayISO}:${normalizeFR(toFRNumber(phone))}`;
          if (licence.automationLog.includes(key)) continue;

          const msg = renderTemplate(tpl, { prenom: c?.prenom || c?.firstName || '', nom: c?.nom || c?.lastName || '' }).trim();
          const r = await sendSmsAutoForLicence({ licence, list, rawRecord, idx:i, numero: phone, text: msg, type:'auto-anniv' });
          if (r.ok) { licence.automationLog.push(key); touched = true; }
        }
      }

      // Renouvellement Lentilles J-10
      if (a.autoLensRenewalEnabled) {
        const advance = Number.isFinite(+a.lensAdvanceDays) ? +a.lensAdvanceDays : 10;
        const tpl = a.messageLensRenewal || 'Bonjour {prenom}, pensez au renouvellement de vos lentilles.';
        for (const c of clients) {
          const endISO = (function computeLensEndISO(client) {
            const end =
              parseToISODate(client?.nextLensRenewal) ||
              parseToISODate(client?.renouvellementLentilles) ||
              parseToISODate(client?.renouvellement) ||
              parseToISODate(client?.lensEndDate);
            if (end) return end;

            const start =
              parseToISODate(client?.lensStartDate) ||
              parseToISODate(client?.dateDernieresLentilles) ||
              parseToISODate(client?.lastLensPurchase) ||
              parseToISODate(client?.dateAchatLentilles);
            if (!start) return null;

            const days =
              Number(client?.lensDurationDays) ||
              Number(client?.renouvellementJours) ||
              Number(client?.dureeLentillesJours) ||
              Number(client?.cycleJours) || 0;

            const months =
              Number(client?.lensDurationMonths) ||
              Number(client?.renouvellementMois) ||
              Number(client?.dureeLentillesMois) || 0;

            if (days > 0) return addDaysISO(start, days);
            if (months > 0) return addMonthsISO(start, months);

            const raw = String(client?.lensDuration || client?.dureeLentilles || '').trim().toLowerCase();
            if (raw) {
              const mJ = /^(\d+)\s*j/.exec(raw);
              const mM = /^(\d+)\s*m/.exec(raw);
              if (mJ) return addDaysISO(start, Number(mJ[1]));
              if (mM) return addMonthsISO(start, Number(mM[1]));
              const n = Number(raw);
              if (Number.isFinite(n) && n > 0) return addDaysISO(start, n);
            }
            return null;
          })(c);

          if (!endISO) continue;
          const triggerISO = addDaysISO(endISO, -advance);
          if (triggerISO !== todayISO) continue;

          const phone = pickClientPhone(c);
          if (!phone) continue;
          const key = `renew:${todayISO}:${normalizeFR(toFRNumber(phone))}`;
          if (licence.automationLog.includes(key)) continue;

          const msg = renderTemplate(tpl, { prenom: c?.prenom || c?.firstName || '', nom: c?.nom || c?.lastName || '' }).trim();
          const r = await sendSmsAutoForLicence({ licence, list, rawRecord, idx:i, numero: phone, text: msg, type:'auto-renew' });
          if (r.ok) { licence.automationLog.push(key); touched = true; }
        }
      }
    }

    if (touched) {
      await jsonbinPutAll(Array.isArray(rawRecord) ? list : list[0] || {});
      console.log('✅ CRON auto: envois et journal sauvegardés.');
    } else {
      console.log('👌 CRON auto: rien à envoyer aujourd’hui.');
    }
  } catch (e) {
    console.error('❌ CRON auto error:', e);
  }
}, { timezone: 'Europe/Paris' });

// =======================
//   Facture PDF
// =======================
app.post('/api/generate-invoice', async (req, res) => {
  const { opticien, type, montant, details, montantHT, montantTTC, tva } = req.body || {};
  if (!opticien || !opticien.id) return res.status(400).json({ error: 'Opticien manquant ou invalide' });

  // ✅ Supporte montant direct OU (HT/TVA/TTC)
  let totalTTC = Number.isFinite(Number(montant)) ? Number(montant) : undefined;
  if (typeof totalTTC === 'undefined') {
    if (Number.isFinite(Number(montantTTC))) totalTTC = Number(montantTTC);
    else if (Number.isFinite(Number(montantHT)) && Number.isFinite(Number(tva))) totalTTC = Number(montantHT) + Number(tva);
  }
  if (!Number.isFinite(totalTTC)) totalTTC = 0;

  const fileName = `facture-${opticien.id}-${uuidv4()}.pdf`;
  const filePath = path.join(__dirname, 'public/factures', fileName);

  const doc = new PDFDocument();
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  doc.fontSize(20).text('Facture OptiCOM', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Nom : ${opticien.nom}`);
  doc.text(`SIRET : ${opticien.siret || '—'}`);
  doc.text(`Email : ${opticien.email}`);
  doc.text(`Téléphone : ${opticien.telephone || '—'}`);
  doc.moveDown();
  doc.text(`Type de facture : ${type}`);
  if (Number.isFinite(Number(montantHT)) && Number.isFinite(Number(tva))) {
    doc.text(`Montant HT : ${Number(montantHT).toFixed(2)} €`);
    doc.text(`TVA : ${Number(tva).toFixed(2)} €`);
  }
  doc.text(`Montant TTC : ${totalTTC.toFixed(2)} €`);
  doc.text(`Détails : ${details}`);
  doc.text(`Date : ${new Date().toLocaleDateString('fr-FR')}`);
  doc.end();

  stream.on('finish', async () => {
    try {
      res.json({ url: `/factures/${fileName}` });
    } catch (err) {
      console.error('❌ Erreur après PDF:', err);
      res.status(500).json({ error: 'PDF généré mais mise à jour échouée' });
    }
  });

  stream.on('error', (err) => {
    console.error('❌ Erreur PDF :', err);
    res.status(500).json({ error: 'Erreur création PDF' });
  });
});

// =======================
//   Lancement serveur
// =======================
app.listen(PORT, () => {
  console.log(`[OptiCOM] Server up on :${PORT} (Node ${process.version})`);
});
