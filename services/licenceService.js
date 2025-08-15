// services/licenceService.js
const { getLatest, putRecord } = require('../clients/jsonbinClient');

function slugify(str='') {
  return String(str).normalize('NFKD')
    .replace(/[\u0300-\u036f]/g,'')       // accents
    .replace(/[^a-zA-Z0-9]+/g,'-')        // non alphanum
    .replace(/^-+|-+$/g,'')               // bords
    .toLowerCase();
}
function genId(name='licence') {
  const base = slugify(name).slice(0,18) || 'licence';
  const rand = Math.random().toString(36).slice(2,8);
  return `lic_${base}_${rand}`;
}
function normSender(s='') {
  const t = String(s).toUpperCase().replace(/[^A-Z0-9]/g,'');
  if (t.length < 3 || t.length > 11) throw new Error('sender doit faire 3 à 11 caractères A-Z/0-9');
  return t;
}

/**
 * createLicence(payload) -> crée et stocke la licence dans db.licences (objet par id)
 * Champs attendus: name (enseigne) [requis], sender [requis], siret?, contact? {name,email,phone}, plan? ('basic'|'pro'|'unlimited'), credits?
 */
async function createLicence(payload){
  if (!payload || !payload.name) throw new Error('name requis');
  if (!payload.sender) throw new Error('sender requis');

  const db = await getLatest();
  if (!db.licences || Array.isArray(db.licences)) db.licences = {}; // dictionnaire par id

  const now = new Date().toISOString();
  const id = payload.id || genId(payload.name);

  if (db.licences[id]) throw new Error(`licence déjà existante: ${id}`);

  const licence = {
    id,
    name: String(payload.name).trim(),
    siret: payload.siret ? String(payload.siret).trim() : null,
    contact: {
      name: payload.contact?.name || null,
      email: payload.contact?.email || null,
      phone: payload.contact?.phone || null,
    },
    sender: normSender(payload.sender),
    plan: payload.plan || 'basic',                    // 'basic' | 'pro' | 'unlimited'
    credits: Number.isFinite(payload.credits) ? Number(payload.credits) : 0,
    cgv: { accepted: false, version: null, acceptedAt: null, textHash: null, ip: null, userAgent: null },
    marketingDefaultOptIn: false,                     // par défaut: pas de consentement
    createdAt: now,
    updatedAt: now,
    // autres champs spécifiques si besoin…
  };

  db.licences[id] = licence;
  await putRecord(db);
  return licence;
}

module.exports = { createLicence };
