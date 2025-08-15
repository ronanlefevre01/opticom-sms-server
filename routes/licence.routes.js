// routes/licence.routes.js
const express = require('express');
const router = express.Router();

const { createLicence } = require('../services/licenceService');
const { requireAdmin } = require('../middleware/adminAuth');
const { getLatest } = require('../clients/jsonbinClient');

// adminAudit est optionnel : on le rend no-op si non présent
let audit = (_req, _res, next) => next();
try {
  const maybeAudit = require('../middleware/adminAudit');
  if (typeof maybeAudit === 'function') audit = maybeAudit;
} catch { /* ignore */ }

// ------- helpers -------
function pickList(licencesStore) {
  // Accepte soit un objet {id: licence}, soit un tableau [licence]
  if (Array.isArray(licencesStore)) return licencesStore;
  if (licencesStore && typeof licencesStore === 'object') return Object.values(licencesStore);
  return [];
}
function findById(licencesStore, id) {
  if (!id) return undefined;
  if (Array.isArray(licencesStore)) return licencesStore.find(l => String(l?.id) === String(id));
  return licencesStore?.[id];
}

// ------- LIST -------
router.get('/admin/licences', requireAdmin, audit, async (_req, res) => {
  try {
    const db = await getLatest();
    const list = pickList(db.licences);
    res.json({ ok: true, licences: list });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ------- CREATE -------
router.post('/admin/licences', requireAdmin, audit, async (req, res) => {
  try {
    const licence = await createLicence(req.body || {});
    res.status(201).json({ ok: true, licence });
  } catch (e) {
    const msg = e.message || 'error';
    const code = /requis|sender|existante|3 à 11/.test(msg) ? 400 : 500;
    res.status(code).json({ ok: false, error: msg });
  }
});

// ------- READ by id -------
router.get('/admin/licences/:id', requireAdmin, audit, async (req, res) => {
  try {
    const db = await getLatest();
    const lic = findById(db.licences, req.params.id);
    if (!lic) return res.status(404).json({ ok: false, error: 'not_found' });
    res.json({ ok: true, licence: lic });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

module.exports = router;
