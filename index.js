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
const multer = require('multer'); // ← AJOUT
const cryptoNode = require('crypto'); // si pas déjà importé

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
      res.setHeader('Content-Disposition', 'inline'); // affiche le PDF dans le navigateur
    },
  })
);


// --- Middlewares globaux ---
app.use(cors());
app.use(bodyParser.json());
app.use('/webhook-stripe', express.raw({ type: 'application/json' }));
app.use(cookieParser());
app.use(express.static('public'));

// ... ton code existant (require('express'), app.use(express.json()), etc.)

const purgeRoutes = require('./routes/purge.routes');
const { schedulePurge } = require('./services/purgeService');

// routes
app.use('/api', purgeRoutes);

// CRON quotidien à 03:00 Europe/Paris
schedulePurge();

// ... ton code existant (app.listen, module.exports, etc.)

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
// Réponse: { ok, numero, filename, url }
app.post('/api/upload-facture', requireAdminToken, upload.single('pdf'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier PDF manquant (champ 'pdf')." });
  const numero = String(req.body.numero || path.basename(req.file.filename, '.pdf'));
  const url = `${req.protocol}://${req.get('host')}/factures/${req.file.filename}`;
  res.json({ ok: true, numero, filename: req.file.filename, url });
});


// =======================
//   JSONBIN HELPERS
// =======================
const must = (v, name) => {
  if (!v) throw new Error(`${name} manquant.`);
  return v;
};

async function jsonbinGetAll() {
  const binId = must(process.env.JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const headers = {
    'X-Bin-Meta': 'false',
    ...(process.env.JSONBIN_API_KEY ? { 'X-Master-Key': process.env.JSONBIN_API_KEY } : {}),
  };
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
  const binId = must(process.env.JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
  const headers = {
    'Content-Type': 'application/json',
    ...(process.env.JSONBIN_API_KEY ? { 'X-Master-Key': process.env.JSONBIN_API_KEY } : {}),
    'X-Bin-Versioning': 'false',
  };
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

    // normalisation: alphanum, 3..11 chars (contraintes opérateur SMS)
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

    // hygiène côté serveur (trim + limite raisonnable)
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

// 1) Statut d’acceptation CGV pour une licence
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

// 2) Enregistrement de l’acceptation CGV (preuve)
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


// Middleware — prépare sender/signature + licence JSONBin (licenceId ou opticienId)
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

    // fallback permissif : pas bloquant si on n'a pas de licence (mais /send-sms vérifiera)
    const candidateSender = sender || licence?.libelleExpediteur || licence?.opticien?.enseigne || 'OptiCOM';
    const normalizedSender = normalizeSender(candidateSender);
    const signatureFromLicence = licence?.signature || '';
    const chosenSignature = (sigFromClient || signatureFromLicence || '').trim();

    // on garde ce qu'il faut si d'autres routes veulent écrire
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
    nomMagasin, // <-- source principale
    email,
    adresse,
    ville,
    codePostal,
    pays,
    formuleId,
    siret,
    telephone
  } = req.body;

  // On prend nomMagasin sinon compatibilité, mais on refuse si vide
  const enseigne = (nomMagasin || req.body.enseigne || req.body.nom || '').trim();
  if (!enseigne) {
    return res.status(400).json({ error: 'Le nom du magasin (enseigne) est obligatoire.' });
  }

  try {
    const session_token = uuidv4();

    const customerData = {
      email,
      company_name: enseigne, // ✅ plus de "Magasin" par défaut
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

    // On stocke toutes les infos nécessaires
    sessionTokenMap.set(session_token, {
      enseigne,
      email,
      adresse,
      ville,
      codePostal,
      pays,
      formuleId,
      siret,
      telephone
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

  const normalizeSender = (raw = 'OptiCOM') => {
    let s = String(raw).toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (s.length < 3) s = 'OPTICOM';
    if (s.length > 11) s = s.slice(0, 11);
    return s;
  };

  try {
    // 1) Confirme le redirect flow
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

    // 2) Récupère les infos mises en session dans /create-mandat
    const opt = sessionTokenMap.get(sessionToken);
    if (!opt) return res.status(400).send('Données opticien manquantes ou session expirée.');

    // 🟢 On prend en priorité nomMagasin si dispo
    const enseigne = opt.nomMagasin || opt.enseigne || 'Opticien sans nom';

    const selectedFormule = formulas.find(f => f.id === opt.formuleId) || { name: 'Formule inconnue', credits: 0 };
    const abonnement = selectedFormule.name;
    const credits    = selectedFormule.credits;

    const licenceKey = uuidv4();

    const libelleExpediteur = normalizeSender(enseigne);

    // 3) Construit la licence
    const newLicence = {
      id: uuidv4(),
      licence: licenceKey,
      dateCreation: new Date().toISOString(),
      abonnement,
      credits,
      libelleExpediteur,
      opticien: {
        id: 'opt-' + Math.random().toString(36).slice(2, 10),
        enseigne, // 🟢 ici toujours le vrai nom magasin
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

    // 4) Sauvegarde JSONBin
    const binId = must(process.env.JSONBIN_BIN_ID, 'JSONBIN_BIN_ID');
    const apiKey = must(process.env.JSONBIN_API_KEY, 'JSONBIN_API_KEY');

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
const lastSent = new Map();                   // key: `${licenceId}:${numeroNormalise}`
const MIN_INTERVAL_MS = 15 * 1000;            // 15 s entre 2 envois au même numéro depuis la même licence

function ymKey(d = new Date()) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

// numéro E.164 « +33… » et version normalisée sans non-chiffres pour clé RL/optout

function normalizeFR(msisdn='') {
  return toFRNumber(msisdn).replace(/\D/g,'');
}

// Créneaux FR prudents: Lun–Sam 08:00–20:00 (heure Paris). Dimanche interdit.
function isQuietHours(date = new Date()) {
  const paris = new Date(date.toLocaleString('en-US', { timeZone: 'Europe/Paris' }));
  const day = paris.getDay();  // 0=Dim..6=Sam
  const hour = paris.getHours();
  return (day === 0) || (hour < 8) || (hour >= 20);
}

// consentement marketing au niveau licence (si présent)
function hasMarketingConsent(licence) {
  const c = licence?.consentements?.marketingSms || licence?.marketingSms;
  return !!(c && c.value && !c.unsubscribedAt);
}

// opt-out ciblé (par numéro)
function isOptedOut(licence, numeroE164) {
  const n = normalizeFR(numeroE164);
  if (Array.isArray(licence?.optOuts) && licence.optOuts.some(x => normalizeFR(x) === n)) return true;
  const c = licence?.consentements?.marketingSms;
  if (c && c.unsubscribedAt) return true;
  return false;
}

// Lien STOP (désinscription)
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

// Journalisation minimale d’un envoi dans la licence (hash du message)
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

// --- Admin Opt-out: export CSV & ajout manuel ---
// Protégées par le même jeton que l’upload de facture (ADMIN_UPLOAD_TOKEN)

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

    const phone = toFRNumber(phoneNumber); // normalise en +33...
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

    // tableau "consents" (pour check rapide) + "consentsLog" (preuve détaillée)
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
    licence.consentsLog = log.slice(-5000); // borne raisonnable

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ success:true });
  } catch (e) {
    console.error('❌ /consent error:', e);
    return res.status(500).json({ success:false, error:'SERVER_ERROR' });
  }
});



// ============================
//   Envoi SMS (tout JSONBin)
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

    // décrémentation éventuelle + journalisation
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


// Alias transactionnel
app.post('/send-transactional', applySenderAndSignature, async (req, res) => {
  req.body = { ...req.body, licenceId: req.body.licenceId, opticienId: req.body.opticienId };
  return app._router.handle(req, res, () => {}, 'post', '/send-sms');
});

// Alias promotionnel (même décrémentation, seul endpoint SMSMode change si besoin)
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

    // Numéro au format FR/E.164
    const numero = toFRNumber(phoneNumber);

    // 🛑 Consentement marketing requis (body ou liste serveur)
    const hasConsent =
      marketingConsent === true ||
      (Array.isArray(licence.consents) && licence.consents.includes(numero)) ||
      licence.marketingConsentGlobal === true;

    if (!hasConsent) {
      return res.status(403).json({ success: false, error: 'CONSENTEMENT_MARKETING_ABSENT' });
    }

    // 📴 Respect du STOP / désinscription déjà faite
    if (isOptedOut(licence, numero)) {
      return res.status(403).json({ success: false, error: 'DESTINATAIRE_DESINSCRIT' });
    }

    // ⏱️ anti-spam : 15s entre 2 envois (licence, numéro)
    const rlKey = `${licence.id}:${numero}`;
    const last = lastSent.get(rlKey) || 0;
    if (Date.now() - last < MIN_INTERVAL_MS) {
      return res
        .status(429)
        .json({ success: false, error: 'Trop rapproché, réessayez dans quelques secondes.' });
    }
    lastSent.set(rlKey, Date.now());

    const { sender, signature } = req.smsContext;

    // ✍️ Ajoute la signature si absente
    const baseText = buildFinalMessage(message || '', signature || '');

    // 🇫🇷 Prospection FR : STOP au 36111 obligatoire (sender alpha)
    function ensureStopMention(text) {
      return /stop\s+au\s+36111/i.test(text) ? text : `${text}\nSTOP au 36111`;
    }
    const finalMessage = ensureStopMention(baseText);

    // Envoi SMSMode
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

    // Décrément crédits si ≠ Illimitée
    if (licence.abonnement !== 'Illimitée') {
      licence.credits = Math.max(0, Number(licence.credits || 0) - 1);
    }

    // Log + persistance JSONBin
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
// Prix et TVA (utilisés pour le calcul TTC)
app.post('/achat-credits-gocardless', async (req, res) => {
  const { email, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity || '1'));

  // 💰 Prix HT & TTC
  const prixHT = 6; // € HT par pack
  const tauxTVA = 0.20;
  const prixTTC = prixHT * (1 + tauxTVA); // 7,20 TTC

  try {
    // 1️⃣ Récupérer licence
    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l =>
      String(l.opticien?.email).toLowerCase() === String(email).toLowerCase()
    );
    if (idx === -1) return res.status(404).json({ error: "Licence introuvable" });

    const mandate = licence.mandateId;
    if (!mandate) return res.status(400).json({ error: "Aucun mandat associé à cette licence" });

    // 2️⃣ Paiement GoCardless (montant TTC)
    const response = await fetch(`${GO_CARDLESS_API_BASE}/payments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify({
        payments: {
          amount: Math.round(prixTTC * qty * 100), // en centimes TTC
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

    // 3️⃣ Ajout des crédits
    const creditsAjoutes = qty * 100;
    licence.credits = (Number(licence.credits) || 0) + creditsAjoutes;
    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    // 4️⃣ Génération facture PDF
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

    // 5️⃣ Réponse finale
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
      // On ne push pas ici dans la licence pour éviter double-édition concurrente.
      // Les routes appelantes (Stripe / GoCardless) ajoutent l’URL dans licence.factures.
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

app.post('/changer-formule', async (req, res) => {
  const { email, nouvelleFormule } = req.body;
  if (!email || !nouvelleFormule) {
    return res.status(400).json({ error: 'Email et nouvelle formule requis' });
  }

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    const { idx, licence } = findLicenceIndex(list, l => String(l.opticien?.email).toLowerCase() === String(email).toLowerCase());
    if (idx === -1) return res.status(404).json({ error: "Licence introuvable" });

    if (!licence.next_payment_date) {
      return res.status(400).json({ error: "Aucune date de renouvellement trouvée" });
    }

    licence.nouvelleFormule = nouvelleFormule;
    licence.dateChangement = licence.next_payment_date; // Activation à la prochaine échéance

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    res.json({ success: true, message: `Formule ${nouvelleFormule} programmée pour le ${licence.dateChangement}` });
  } catch (err) {
    console.error('❗ Erreur changer-formule :', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/resiliation-abonnement', async (req, res) => {
  try {
    const { email, licenceId } = req.body || {};
    if (!email && !licenceId) {
      return res.status(400).json({ success: false, error: 'EMAIL_OU_LICENCE_ID_REQUIS' });
    }

    const { list, rawRecord } = await jsonbinGetAll();

    let { idx, licence } =
      licenceId
        ? findLicenceIndex(list, l => String(l.id) === String(licenceId))
        : findLicenceIndex(list, l => String(l.opticien?.email).toLowerCase() === String(email).toLowerCase());

    if (idx === -1) return res.status(404).json({ success: false, error: 'LICENCE_INTROUVABLE' });

    // On prend la prochaine échéance connue pour la date de fin
    const dateResiliation =
      licence.renouvellement || licence.next_payment_date || new Date().toISOString().slice(0, 10);

    licence.resiliationDemandee = true;
    licence.dateResiliation = dateResiliation;

    const bodyToPut = Array.isArray(rawRecord) ? (list[idx] = licence, list) : licence;
    await jsonbinPutAll(bodyToPut);

    return res.json({ success: true, dateResiliation });
  } catch (e) {
    console.error('❌ /resiliation-abonnement error:', e);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// --- Expose la liste des licences (lecture seule) ---
app.get('/api/licences', async (req, res) => {
  try {
    const { list } = await jsonbinGetAll(); // utilise JSONBIN_BIN_ID + JSONBIN_API_KEY côté Render
    res.json(Array.isArray(list) ? list : (list ? [list] : []));
  } catch (e) {
    console.error('❌ /api/licences error:', e);
    res.status(500).json({ error: 'JSONBIN_READ_FAILED', detail: String(e.message || e) });
  }
});



const cron = require('node-cron');

const ISO = (d = new Date()) => d.toISOString().slice(0, 10); // YYYY-MM-DD

// Montants (centimes) par formule pour GoCardless
const TARIFS_GC = { Starter: 600, Pro: 1200, Premium: 1800 };

cron.schedule('0 3 * * *', async () => { // tous les jours à 03:00
  console.log('⏳ CRON: vérification formules & résiliations...');
  const today = ISO();

  try {
    const { list, rawRecord } = await jsonbinGetAll();
    let updated = false;
    const toDelete = []; // indices licences à supprimer du JSONBin

    for (let i = 0; i < list.length; i++) {
      const licence = list[i];

      // ---------- 1) CHANGEMENT DE FORMULE À L’ÉCHÉANCE ----------
      if (licence.nouvelleFormule && licence.dateChangement) {
        if (today >= String(licence.dateChangement).slice(0, 10)) {
          const newPlan = String(licence.nouvelleFormule);
          console.log(`🔄 Passage de ${licence.opticien?.email} à la formule ${newPlan}`);

          // Mets à jour le champ *abonnement* (actuelle source dans le front)
          licence.abonnement = newPlan;
          delete licence.nouvelleFormule;
          delete licence.dateChangement;
          updated = true;

          // Ajuste le montant GoCardless si on a un subscriptionId
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

      // ---------- 2) RÉSILIATION À LA DATE PROGRAMMÉE ----------
      if (licence.resiliationDate) {
        const cut = String(licence.resiliationDate).slice(0, 10);
        if (today >= cut) {
          console.log(`🛑 Résiliation effective pour ${licence.opticien?.email} (date ${cut})`);

          // Arrête les débits côté GoCardless (subscription si présente, sinon mandat)
          try {
            if (licence.subscriptionId) {
              // annule l’abonnement (immédiat)
              await fetch(`${GO_CARDLESS_API_BASE}/subscriptions/${licence.subscriptionId}/actions/cancel`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
                  'GoCardless-Version': '2015-07-06',
                },
                body: JSON.stringify({}), // rien à passer
              });
              console.log(`✅ Subscription annulée pour ${licence.opticien?.email}`);
            } else if (licence.mandateId) {
              // pas d’abonnement géré : on annule le mandat pour bloquer tout futur débit
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

          // Supprime la licence du JSONBin pour bloquer l’accès depuis l’app
          licence.active = false;
delete licence.licence;        // optionnel: retirer la clé d’accès
delete licence.credits;        // optionnel
updated = true;

        }
      }
    }

    // ---------- 3) ÉCRITURE JSONBIN ----------
    if (toDelete.length) {
      // supprime en partant de la fin pour conserver les index
      toDelete.sort((a, b) => b - a).forEach(idx => list.splice(idx, 1));
      updated = true;
      console.log(`🧹 ${toDelete.length} licence(s) supprimée(s) du JSONBin (résiliation).`);
    }

    if (updated) {
      // jsonbinPutAll sait gérer array vs objet unique via rawRecord
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
//   Lancement serveur
// =======================
app.listen(PORT, () => {
  console.log(`✅ Serveur prêt sur http://localhost:${PORT}`);
});
