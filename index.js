require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
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

const licenceRoutes = require('./routes/licence.routes');
const purgeRoutes = require('./routes/purge.routes');
const { schedulePurge } = require('./services/purgeService');

// --- JSONBin config (une seule clé, deux noms possibles côté env) ---
const JSONBIN_BIN_ID = process.env.JSONBIN_BIN_ID;
const JSONBIN_KEY = process.env.JSONBIN_MASTER_KEY || process.env.JSONBIN_API_KEY; // accepte l’un ou l’autre

// ---- CGV (version + texte brut Markdown + hash) ----
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

// fetch (ESM compat)
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 3001;

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const GO_CARDLESS_API_BASE = 'https://api.gocardless.com';

const goCardlessClient = goCardless(
  process.env.GOCARDLESS_API_KEY,
  process.env.GOCARDLESS_ENV || 'live'
);

const sessionTokenMap = new Map();

// --- Formules ---
const formulas = [
  { id: 'starter', name: 'Starter', credits: 100 },
  { id: 'pro', name: 'Pro', credits: 300 },
  { id: 'premium', name: 'Premium', credits: 600 },
  { id: 'alacarte', name: 'À la carte', credits: 0 },
];

// --- Dossier factures public ---
const factureDir = path.join(__dirname, 'public/factures');
if (!fs.existsSync(factureDir)) fs.mkdirSync(factureDir, { recursive: true });

// Servir les PDF publiquement : https://<host>/factures/<fichier>.pdf
app.use(
  '/factures',
  express.static(factureDir, {
    index: false,
    maxAge: '1y',
    setHeaders: (res) => {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.setHeader('Content-Disposition', 'inline');
    },
  })
);

// --- Middlewares globaux ---
app.use(cors());
app.use(cookieParser());
// ⚠️ ne PAS mettre express.raw globalement ; on l’applique uniquement sur /webhook-stripe
app.use(bodyParser.json());
app.use(express.static('public'));

// Routes modules
app.use('/api', licenceRoutes);
app.use('/api', purgeRoutes);

// CRON quotidien à 03:00 Europe/Paris
schedulePurge();

// --- Ping ---
app.get('/', (_, res) => res.send('✅ Serveur OptiCOM en ligne'));

// ===== Upload de facture (PDF) protégé par token =====
const ADMIN_UPLOAD_TOKEN = process.env.ADMIN_UPLOAD_TOKEN;

function requireAdminToken(req, res, next) {
  if (!ADMIN_UPLOAD_TOKEN) return res.status(500).json({ error: 'ADMIN_UPLOAD_TOKEN manquant côté serveur' });
  const auth = req.get('authorization') || '';
  if (auth !== `Bearer ${ADMIN_UPLOAD_TOKEN}`) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// Multer: enregistre directement le fichier dans public/factures
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, factureDir),
  filename: (req, _file, cb) => {
    const numero = (req.body.numero && String(req.body.numero).trim()) || uuidv4();
    const safe = numero.replace(/[^A-Za-z0-9-_]/g, '_');
    cb(null, `${safe}.pdf`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15 MB
  fileFilter: (_req, file, cb) => cb(null, file.mimetype === 'application/pdf'),
});

// POST /api/upload-facture  (form-data: numero?, pdf)
app.post('/api/upload-facture', requireAdminToken, upload.single('pdf'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier PDF manquant (champ 'pdf')." });
  const numero = String(req.body.numero || path.basename(req.file.filename, '.pdf'));
  const url = `${req.protocol}://${req.get('host')}/factures/${req.file.filename}`;
  res.json({ ok: true, numero, filename: req.file.filename, url });
});

// =======================
//   JSONBIN HELPERS
// =======================
const must = (v, name) => { if (!v) throw new Error(`${name} manquant.`); return v; };

async function jsonbinGetAll() {
  const binId = must(JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const headers = { 'X-Bin-Meta': 'false' };
  if (JSONBIN_KEY) headers['X-Master-Key'] = JSONBIN_KEY;

  const r = await fetch(`https://api.jsonbin.io/v3/b/${binId}/latest`, { headers });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`Erreur JSONBin (${r.status}): ${t}`);
  }
  const data = await r.json();
  const record = data?.record ?? data;
  const list = Array.isArray(record) ? record : [record];
  return { list, rawRecord: record };
}

async function jsonbinPutAll(body) {
  const binId = must(JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const headers = { 'Content-Type': 'application/json', 'X-Bin-Versioning': 'false' };
  if (JSONBIN_KEY) headers['X-Master-Key'] = JSONBIN_KEY;

  const r = await fetch(`https://api.jsonbin.io/v3/b/${binId}`, {
    method: 'PUT',
    headers,
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(`Erreur mise à jour JSONBin: ${t}`);
  }
}

// ✅ utilitaire manquant
function findLicenceIndex(list, predicate) {
  const idx = list.findIndex(predicate);
  return { idx, licence: idx >= 0 ? list[idx] : null };
}

// =======================
//   Licence update helper
// =======================
async function updateLicenceFields({ licenceId, opticienId, patch = {} }) {
  const { list, rawRecord } = await jsonbinGetAll();

  const { idx, licence } = findLicenceIndex(
    list,
    (l) =>
      (licenceId && String(l.id) === String(licenceId)) ||
      (opticienId && String(l.opticien?.id) === String(opticienId))
  );
  if (idx === -1 || !licence) {
    return { ok: false, status: 404, error: 'LICENCE_NOT_FOUND' };
  }

  const updated = { ...licence, ...patch, updatedAt: new Date().toISOString() };
  const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = updated, list) : updated;
  await jsonbinPutAll(bodyToPut);

  return { ok: true, licence: updated };
}

// =======================
//   Licence: expéditeur
// =======================
app.post('/licence/expediteur', async (req, res) => {
  try {
    const { licenceId, opticienId, libelleExpediteur } = req.body || {};
    if (!libelleExpediteur) {
      return res.status(400).json({ success: false, error: 'LIBELLE_MANQUANT' });
    }

    // normalisation: alphanum, 3..11 chars
    const cleaned = String(libelleExpediteur).replace(/[^a-zA-Z0-9]/g, '').slice(0, 11);
    if (cleaned.length < 3) {
      return res.status(400).json({ success: false, error: 'LIBELLE_INVALIDE' });
    }

    const { list, rawRecord } = await jsonbinGetAll();

    let found = { idx: -1, licence: null };
    if (licenceId) {
      found = findLicenceIndex(list, l => String(l.id) === String(licenceId));
    } else if (opticienId) {
      found = findLicenceIndex(list, l => String(l.opticien?.id) === String(opticienId));
    }
    if (found.idx === -1) {
      return res.status(404).json({ success: false, error: 'LICENCE_INTRouvable' });
    }

    list[found.idx].libelleExpediteur = cleaned;

    const bodyToPut = Array.isArray(rawRecord) ? list : list[found.idx];
    await jsonbinPutAll(bodyToPut);

    res.json({ success: true, licence: list[found.idx] });
  } catch (e) {
    console.error('❌ /licence/expediteur error:', e);
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// =======================
//   Licence: signature SMS
// =======================
app.post('/licence/signature', async (req, res) => {
  try {
    const { licenceId, opticienId, signature } = req.body || {};
    if (typeof signature !== 'string') {
      return res.status(400).json({ success: false, error: 'SIGNATURE_MANQUANTE' });
    }

    const clean = String(signature).trim().slice(0, 200);

    const result = await updateLicenceFields({
      licenceId,
      opticienId,
      patch: { signature: clean },
    });

    if (!result.ok) {
      return res.status(result.status || 500).json({ success: false, error: result.error });
    }
    return res.json({ success: true, licence: result.licence });
  } catch (e) {
    console.error('❌ /licence/signature error:', e);
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// 1) Statut d’acceptation CGV
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
    const absoluteUrl = `${req.protocol}://${req.get('host')}/legal/cgv-${CGV_VERSION}.md`;

    res.json({
      licenceId,
      currentVersion: CGV_VERSION,
      accepted,
      acceptedVersion: licence.cgv?.version || null,
      acceptedAt: licence.cgv?.acceptedAt || null,
      textUrl: absoluteUrl,
      serverTextHash: CGV_TEXT_HASH || null,
    });
  } catch (e) {
    console.error('❌ /licence/cgv-status', e);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// 2) Enregistrement de l’acceptation CGV
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
//   SMS & SIGNATURE
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

// Middleware — prépare sender/signature + licence JSONBin
async function applySenderAndSignature(req, res, next) {
  try {
    const { sender, signature: sigFromClient, licenceId, opticienId } = req.body || {};
    const { list, rawRecord } = await jsonbinGetAll();

    let { idx, licence } = findLicenceIndex(
      list,
      (l) =>
        (licenceId && String(l.id) === String(licenceId)) ||
        (opticienId && String(l.opticien?.id) === String(opticienId))
    );

    const candidateSender = sender || licence?.libelleExpediteur || licence?.opticien?.enseigne || 'OptiCOM';
    const normalizedSender = normalizeSender(candidateSender);
    const signatureFromLicence = licence?.signature || '';
    const chosenSignature = (sigFromClient || signatureFromLicence || '').trim();

    req._jsonbin = { list, rawRecord, idx, licence };
    req.smsContext = { licence, idx, sender: normalizedSender, signature: chosenSignature };
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
    formuleId, siret, telephone
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
      country_code: pays || 'FR',
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

    sessionTokenMap.set(session_token, {
      enseigne, email, adresse, ville, codePostal, pays, formuleId, siret, telephone
    });

    res.status(200).json({ url: data.redirect_flows.redirect_url });
  } catch (err) {
    console.error('❗ Exception GoCardless:', err);
    res.status(500).json({ error: 'Erreur serveur GoCardless. Veuillez réessayer.' });
  }
});

app.get('/validation-mandat', async (req, res) => {
  const redirectFlowId = req.query.redirect_flow_id;
  const sessionToken   = req.query.session_token;
  if (!redirectFlowId || !sessionToken) {
    return res.status(400).send('Paramètre manquant ou session expirée.');
  }

  const normalizeSenderUpper = (raw = 'OptiCOM') => {
    let s = String(raw).toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (s.length < 3) s = 'OPTICOM';
    if (s.length > 11) s = s.slice(0, 11);
    return s;
  };

  try {
    const confirmResponse = await goCardlessClient.redirectFlows.complete(
      redirectFlowId,
      { session_token: sessionToken }
    );

    const flow = confirmResponse;
    if (!flow || !flow.links || !flow.links.customer) {
      console.error('❌ Erreur GoCardless : réponse invalide', confirmResponse);
      return res.status(500).send('Erreur GoCardless : réponse invalide lors de la confirmation.');
    }

    const customerId = flow.links.customer;
    const mandateId  = flow.links.mandate;

    const opt = sessionTokenMap.get(sessionToken);
    if (!opt) return res.status(400).send('Données opticien manquantes ou session expirée.');

    const enseigne = opt.nomMagasin || opt.enseigne || 'Opticien sans nom';
    const selectedFormule = formulas.find(f => f.id === opt.formuleId) || { name: 'Formule inconnue', credits: 0 };
    const abonnement = selectedFormule.name;
    const credits    = selectedFormule.credits;

    const licenceKey = uuidv4();
    const libelleExpediteur = normalizeSenderUpper(enseigne);

    const newLicence = {
      id: uuidv4(),
      licence: licenceKey,
      dateCreation: new Date().toISOString(),
      abonnement,
      credits,
      libelleExpediteur,
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

    // Sauvegarde JSONBin
    const binId = must(JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
    const apiKey = must(JSONBIN_KEY, 'JSONBIN_KEY');

    const getResponse = await axios.get(`https://api.jsonbin.io/v3/b/${binId}/latest`, {
      headers: { 'X-Master-Key': apiKey, 'X-Bin-Meta': 'false' }
    });

    const record = getResponse.data?.record ?? getResponse.data;
    const list   = Array.isArray(record) ? record : (record ? [record] : []);
    list.push(newLicence);

    const bodyToPut = Array.isArray(record) ? list : newLicence;

    await axios.put(`https://api.jsonbin.io/v3/b/${binId}`, bodyToPut, {
      headers: {
        'Content-Type': 'application/json',
        'X-Master-Key': apiKey,
        'X-Bin-Versioning': 'false'
      }
    });

    sessionTokenMap.delete(sessionToken);

    if (req.headers.accept?.includes('application/json')) {
      return res.json(newLicence);
    }

    res.send(`
      <html>
        <head>
          <title>Licence validée</title>
          <meta charset="utf-8" />
          <style>
            body { font-family: sans-serif; padding: 30px; background: #f7f7f7; }
            .box { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 640px; margin: 0 auto; }
            h1 { color: #2e7d32; }
            code { background: #eee; padding: 5px 10px; font-size: 1.2em; border-radius: 5px; }
            .row { display: flex; align-items: center; gap: 10px; }
            .copy-btn { padding: 6px 10px; border: none; background: #2e7d32; color: #fff; border-radius: 6px; cursor: pointer; }
            .copy-btn:hover { background: #256628; }
            .hint { color: #666; font-size: 0.95em; }
          </style>
        </head>
        <body>
          <div class="box">
            <h1>🎉 Votre mandat est validé !</h1>
            <p class="hint">Voici votre clé de licence :</p>
            <p class="row">
              <code id="licenceKey">${licenceKey}</code>
              <button class="copy-btn" onclick="copyLicence()">📋 Copier</button>
            </p>
            <p>Vous pouvez maintenant retourner dans l'application OptiCOM et la saisir dans l'onglet <strong>« J'ai déjà une licence »</strong>.</p>
          </div>

          <script>
            function copyLicence() {
              const txt = document.getElementById('licenceKey').textContent;
              navigator.clipboard.writeText(txt).then(() => {
                alert('Clé copiée !');
              }).catch(err => {
                alert('Impossible de copier la clé : ' + err);
              });
            }
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

// anti spam léger par (licenceId, numéro)
const lastSent = new Map();
const MIN_INTERVAL_MS = 15 * 1000;

function ymKey(d = new Date()) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
}
function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}
function normalizeFR(msisdn='') {
  return toFRNumber(msisdn).replace(/\D/g,'');
}
function isQuietHours(date = new Date()) {
  const paris = new Date(date.toLocaleString('en-US', { timeZone: 'Europe/Paris' }));
  const day = paris.getDay();  // 0=Dim..6=Sam
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
function hmacShort(input='') {
  return crypto.createHash('sha256').update(String(input)).digest('hex').slice(0,16);
}
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
  licence.historiqueSms = Array.isArray(licence.historiqueSms) ? licence.historiqueSms : [];
  licence.historiqueSms.push(entry);
  const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
  await jsonbinPutAll(bodyToPut);
}

// --- Routes opt-out ---
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

// --- Admin Opt-out ---
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
//   Envoi SMS (JSONBin)
// ============================
async function sendSmsTransactional(req, res) {
  const { phoneNumber, message, licenceId, opticienId } = req.body || {};
  if (!phoneNumber || !message || (!licenceId && !opticienId)) {
    return res.status(400).json({ success: false, error: 'Champs manquants.' });
  }
  if (!process.env.SMSMODE_LOGIN || !process.env.SMSMODE_PASSWORD) {
    return res.status(500).json({ success: false, error: 'SMSMODE_LOGIN / SMSMODE_PASSWORD manquants.' });
  }

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    const found = licenceId
      ? findLicenceIndex(list, l => String(l.id) === String(licenceId))
      : findLicenceIndex(list, l => String(l.opticien?.id) === String(opticienId));
    if (found.idx === -1) return res.status(403).json({ success:false, error:'Licence introuvable.' });
    const licence = found.licence;

    if (licence.abonnement !== 'Illimitée') {
      const credits = Number(licence.credits || 0);
      if (!Number.isFinite(credits) || credits < 1) {
        return res.status(403).json({ success:false, error:'Crédits insuffisants.' });
      }
    }

    const numero = toFRNumber(phoneNumber);

    // ⏱️ anti-spam 15s par (licence, numéro)
    const rlKey = `${licence.id}:${normalizeFR(numero)}`;
    const last = lastSent.get(rlKey) || 0;
    if (Date.now() - last < MIN_INTERVAL_MS) {
      return res.status(429).json({ success:false, error:'Trop rapproché, réessayez dans quelques secondes.' });
    }
    lastSent.set(rlKey, Date.now());

    const { sender, signature } = req.smsContext;
    const finalMessage = buildFinalMessage(message, signature);

    const params = new URLSearchParams();
    params.append('pseudo', process.env.SMSMODE_LOGIN);
    params.append('pass', process.env.SMSMODE_PASSWORD);
    params.append('message', finalMessage);
    params.append('unicode', '1');
    params.append('charset', 'UTF-8');
    params.append('smslong', '1');
    params.append('numero', numero);
    params.append('emetteur', sender);

    const smsResp = await fetch('https://api.smsmode.com/http/1.6/sendSMS.do', {
      method:'POST',
      headers:{ 'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8' },
      body: params.toString(),
    });
    const smsText = await smsResp.text();

    const smsHasError =
      !smsResp.ok || /^32\s*\|/i.test(smsText) || /^35\s*\|/i.test(smsText) || /\berror\b/i.test(smsText);
    if (smsHasError) {
      return res.status(502).json({ success:false, error:`Erreur SMSMode: ${smsText}` });
    }

    if (licence.abonnement !== 'Illimitée') {
      licence.credits = Math.max(0, Number(licence.credits || 0) - 1);
    }
    await appendSmsLogAndPersist({
      list, rawRecord, idx: found.idx, licence,
      entry: {
        date: new Date().toISOString(),
        type: 'transactional',
        numero,
        emetteur: sender,
        textHash: sha256Hex(finalMessage),
        provider: 'smsmode',
        bytes: Buffer.byteLength(finalMessage, 'utf8'),
        mois: ymKey(new Date())
      }
    });

    return res.json({
      success:true,
      licenceId: licence.id,
      credits: licence.credits,
      abonnement: licence.abonnement,
      sender,
      message: finalMessage
    });
  } catch (err) {
    console.error('Erreur /send-sms:', err);
    res.status(500).json({ success:false, error:String(err.message || err) });
  }
}

app.post('/send-sms', applySenderAndSignature, sendSmsTransactional);
app.post('/send-transactional', applySenderAndSignature, sendSmsTransactional);

// Alias promotionnel
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

    const numero = toFRNumber(phoneNumber);

    const hasConsent =
      marketingConsent === true ||
      (Array.isArray(licence.consents) && licence.consents.includes(numero)) ||
      licence.marketingConsentGlobal === true;

    if (!hasConsent) {
      return res.status(403).json({ success: false, error: 'CONSENTEMENT_MARKETING_ABSENT' });
    }

    if (isOptedOut(licence, numero)) {
      return res.status(403).json({ success: false, error: 'DESTINATAIRE_DESINSCRIT' });
    }

    const rlKey = `${licence.id}:${numero}`;
    const last = lastSent.get(rlKey) || 0;
    if (Date.now() - last < MIN_INTERVAL_MS) {
      return res
        .status(429)
        .json({ success: false, error: 'Trop rapproché, réessayez dans quelques secondes.' });
    }
    lastSent.set(rlKey, Date.now());

    const { sender, signature } = req.smsContext;
    const baseText = buildFinalMessage(message || '', signature || '');

    function ensureStopMention(text) {
      return /stop\s+au\s+36111/i.test(text) ? text : `${text}\nSTOP au 36111`;
    }
    const finalMessage = ensureStopMention(baseText);

    const params = new URLSearchParams();
    params.append('pseudo', process.env.SMSMODE_LOGIN);
    params.append('pass', process.env.SMSMODE_PASSWORD);
    params.append('message', finalMessage);
    params.append('unicode', '1');
    params.append('charset', 'UTF-8');
    params.append('smslong', '1');
    params.append('numero', numero);
    params.append('emetteur', sender);

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

    if (licence.abonnement !== 'Illimitée') {
      licence.credits = Math.max(0, Number(licence.credits || 0) - 1);
    }

    await appendSmsLogAndPersist({
      list,
      rawRecord,
      idx: found.idx,
      licence,
      entry: {
        date: new Date().toISOString(),
        type: 'marketing',
        numero,
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
    });
  } catch (err) {
    console.error('Erreur /send-promotional:', err);
    res.status(500).json({ success: false, error: String(err.message || err) });
  }
});

// ===================================
//   Achat de crédits via GoCardless
// ===================================
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
    if (idx === -1) return res.status(404).json({ error: "Licence introuvable" });

    const mandate = licence.mandateId;
    if (!mandate) return res.status(400).json({ error: "Aucun mandat associé à cette licence" });

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

      const factureResponse = await fetch(`https://opticom-sms-server.onrender.com/api/generate-invoice`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(facturePayload)
      });

      const factureData = await factureResponse.json();
      console.log("✅ Facture générée :", factureData);

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
//   Stripe: checkout + WH
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
          unit_amount: 1700,
        },
        quantity: qty,
      }],
      success_url: `opticom://merci-achat?credits=${qty * 100}`,
      cancel_url: 'opticom://annulation-achat',
      metadata: { email: clientEmail || '', quantity: String(qty) },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('❗Erreur Stripe:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la session Stripe.' });
  }
});

// ⚠️ webhook: raw UNIQUEMENT sur la route
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

          // Générer facture PDF
          const facturePayload = {
            opticien: list[idx].opticien,
            type: 'Achat de crédits SMS (Stripe)',
            montant: 17 * quantity,
            details: `${creditsAjoutes} crédits achetés`
          };
          let invoiceUrl = null;
          try {
            const response = await fetch(`http://localhost:${PORT}/api/generate-invoice`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(facturePayload),
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

// Normalisation tolérante pour comparaison de clés
function normKey(s = '') {
  return String(s).replace(/[\s-]/g, '').toUpperCase();
}

// Recherche générique
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

// ✅ Route unifiée + alias rétrocompat
app.get(['/api/licence/by-key', '/licence/by-key', '/licence-by-key', '/api/licence', '/licence'], async (req, res) => {
  try {
    const cle = req.query.cle || req.query.key || req.query.k;
    const id  = req.query.id; // optionnel
    if (!cle && !id) return res.status(400).json({ error: 'Paramètre cle ou id requis' });

    const licence = await findLicence({ cle, id });
    if (!licence) return res.status(404).json({ error: 'LICENCE_INTROUVABLE' });

    res.set('Cache-Control', 'no-store');
    return res.json({ licence });
  } catch (e) {
    console.error('❌ /licence/by-key error:', e);
    return res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

// Expose la liste (lecture seule)
app.get('/api/licences', async (req, res) => {
  try {
    const { list } = await jsonbinGetAll();
    res.json(Array.isArray(list) ? list : (list ? [list] : []));
  } catch (e) {
    console.error('❌ /api/licences error:', e);
    res.status(500).json({ error: 'JSONBIN_READ_FAILED', detail: String(e.message || e) });
  }
});

// =======================
//   Préférences auto (NEW)
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
      messageLensRenewal: a.messageLensRenewal || 'Bonjour {prenom}, pensez au renouvellement de vos lentilles.',
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
      messageLensRenewal: cleanStr(messageLensRenewal, 'Bonjour {prenom}, pensez au renouvellement de vos lentilles.'),
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

// =======================
//   CRON formules / résiliation
// =======================
const cron = require('node-cron');
const ISO = (d = new Date()) => d.toISOString().slice(0, 10); // YYYY-MM-DD
const TARIFS_GC = { Starter: 600, Pro: 1200, Premium: 1800 };

cron.schedule('0 3 * * *', async () => {
  console.log('⏳ CRON: vérification formules & résiliations...');
  const today = ISO();

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    let updated = false;

    for (let i = 0; i < list.length; i++) {
      const licence = list[i];

      // 1) Changement de formule
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
                  'GoCardless-Version': '2015-07-06',
                },
                body: JSON.stringify({ subscriptions: { amount } }),
              });
              console.log(`✅ Subscription mise à jour (${amount} centimes) pour ${licence.opticien?.email}`);
            } catch (e) {
              console.error('❌ GC update subscription amount:', e);
            }
          }
        }
      }

      // 2) Résiliation programmée (accepte dateResiliation ou resiliationDate)
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
                  'GoCardless-Version': '2015-07-06',
                },
                body: JSON.stringify({}),
              });
              console.log(`✅ Subscription annulée pour ${licence.opticien?.email}`);
            } else if (licence.mandateId) {
              await fetch(`${GO_CARDLESS_API_BASE}/mandates/${licence.mandateId}/actions/cancel`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
                  'GoCardless-Version': '2015-07-06',
                },
                body: JSON.stringify({}),
              });
              console.log(`✅ Mandat annulé pour ${licence.opticien?.email}`);
            }
          } catch (e) {
            console.error('❌ GC cancel (subscription/mandate):', e);
          }

          // Désactivation
          licence.active = false;
          delete licence.licence; // optionnel: retirer la clé d’accès
          delete licence.credits; // optionnel
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
});

// =======================
//   Automatisation (NEW)
//   - Anniversaire (jour J)
//   - Renouvellement lentilles : J-10 (configurable via lensAdvanceDays)
// =======================

// ====== Helpers dates (Europe/Paris) ======
const PARIS_TZ = 'Europe/Paris';

function isoTodayParis() {
  const d = new Date(new Date().toLocaleString('en-US', { timeZone: PARIS_TZ }));
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2,'0');
  const day = String(d.getDate()).padStart(2,'0');
  return `${y}-${m}-${day}`;
}

// "YYYY-MM-DD" -> Date (UTC) à minuit
function dateFromISO(iso) {
  const [y,m,d] = String(iso).split('-').map(Number);
  if (!y || !m || !d) return null;
  return new Date(Date.UTC(y, m-1, d, 0, 0, 0));
}

// "DD/MM/YYYY" -> "YYYY-MM-DD"
function frToISO(s) {
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(String(s).trim());
  if (!m) return null;
  const [_, dd, mm, yyyy] = m;
  return `${yyyy}-${mm}-${dd}`;
}

// parse "YYYY-MM-DD" OU "DD/MM/YYYY" -> "YYYY-MM-DD"
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

// STOP 36111 si absent
function ensureStopMention(text) {
  return /stop\s+au\s+36111/i.test(text) ? text : `${text}\nSTOP au 36111`;
}

// interpolation simple {prenom} {nom}
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

// lecture numéro client
function pickClientPhone(c) {
  return c?.phone || c?.telephone || c?.mobile || c?.gsm || '';
}

// calcul de la date "fin de lentilles"
function computeLensEndISO(client) {
  // 1) fin explicite
  const end =
    parseToISODate(client?.nextLensRenewal) ||
    parseToISODate(client?.renouvellementLentilles) ||
    parseToISODate(client?.renouvellement) ||
    parseToISODate(client?.lensEndDate);
  if (end) return end;

  // 2) début + durée
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

  // 3) durée textuelle "90", "90j", "6", "6m"
  const raw = String(client?.lensDuration || client?.dureeLentilles || '').trim().toLowerCase();
  if (raw) {
    const mJ = /^(\d+)\s*j/.exec(raw);
    const mM = /^(\d+)\s*m/.exec(raw);
    if (mJ) return addDaysISO(start, Number(mJ[1]));
    if (mM) return addMonthsISO(start, Number(mM[1]));
    const n = Number(raw);
    if (Number.isFinite(n) && n > 0) {
      // par défaut on interprète comme jours
      return addDaysISO(start, n);
    }
  }
  return null;
}

// envoi réel (SMSMode) + décrément + logs + anti-doublon
async function sendSmsAutoForLicence({ licence, list, rawRecord, idx, numero, text, type }) {
  if (!process.env.SMSMODE_LOGIN || !process.env.SMSMODE_PASSWORD) return { ok:false, reason:'SMSMODE_ENV_MISSING' };

  // anti double envoi très rapproché (licence, numéro)
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
    method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8' }, body: params.toString(),
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
      mois: ymKey(new Date()),
    },
  });

  return { ok:true };
}

// Tous les jours à 09:15 Europe/Paris
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

      // ---------- Anniversaire (jour J) ----------
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

      // ---------- Renouvellement Lentilles J-10 ----------
      if (a.autoLensRenewalEnabled) {
        const advance = Number.isFinite(+a.lensAdvanceDays) ? +a.lensAdvanceDays : 10; // J-10 par défaut
        const tpl = a.messageLensRenewal || 'Bonjour {prenom}, pensez au renouvellement de vos lentilles.';
        for (const c of clients) {
          const endISO = computeLensEndISO(c);
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
//   Facture PDF (JSONBin)
// =======================
app.post('/api/generate-invoice', async (req, res) => {
  const { opticien, type, montant, details } = req.body || {};
  if (!opticien || !opticien.id) return res.status(400).json({ error: 'Opticien manquant ou invalide' });

  const fileName = `facture-${opticien.id}-${uuidv4()}.pdf`;
  const filePath = path.join(__dirname, 'public/factures', fileName);

  const doc = new PDFDocument();
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  doc.fontSize(20).text('📄 Facture OptiCOM', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Nom : ${opticien.nom}`);
  doc.text(`SIRET : ${opticien.siret || '—'}`);
  doc.text(`Email : ${opticien.email}`);
  doc.text(`Téléphone : ${opticien.telephone || '—'}`);
  doc.moveDown();
  doc.text(`Type de facture : ${type}`);
  doc.text(`Montant TTC : ${Number(montant).toFixed(2)} €`);
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

// Petit ping JSON brut pour debug local
app.get('/api/ping', (_, res) => res.json({ ok: true }));

// =======================
//   Lancement serveur
// =======================
app.listen(PORT, () => {
  console.log(`✅ Serveur prêt sur http://localhost:${PORT}`);
});
