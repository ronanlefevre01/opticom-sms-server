// routes/purge.routes.js
// (si ton fichier s'appelle purge.route.js, ajuste le require dans index.js)
const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const { runPurge } = require('../services/purgeService');
const { requireAdmin } = require('../middleware/adminAuth');
const { getLatest } = require('../clients/jsonbinClient');

/* ---------- helpers ---------- */
function safeEqual(a, b) {
  const A = Buffer.from(String(a), 'utf8');
  const B = Buffer.from(String(b), 'utf8');
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}
function readSecret() {
  return (process.env.PURGE_WEBHOOK_KEY || '').trim();
}
function readParamKey(req) {
  // gère %xx, espaces, et éventuels slashs finaux
  return decodeURIComponent((req.params.key || '').trim().replace(/\/+$/, ''));
}

/* ---------- 1) Purge manuelle protégée (Bearer token admin) ---------- */
router.post('/internal/purge', requireAdmin, async (req, res) => {
  try {
    const out = await runPurge();
    res.json(out); // { ok:true, removed:{...} }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------- 2) Purge via URL secrète (webhook simple) ----------
   URL : GET /api/purge/<PURGE_WEBHOOK_KEY>
------------------------------------------------------------------ */
router.get('/purge/:key', async (req, res) => {
  const secret = readSecret();
  if (!secret) return res.status(500).json({ error: 'PURGE_WEBHOOK_KEY missing' });

  const provided = readParamKey(req);
  if (!safeEqual(provided, secret)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  try {
    const out = await runPurge();
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------- 3) Self-test JSONBin (lecture seule) ----------
   URL : GET /api/selftest/<PURGE_WEBHOOK_KEY>
------------------------------------------------------------ */
router.get('/selftest/:key', async (req, res) => {
  const secret = readSecret();
  if (!secret) return res.status(500).json({ error: 'PURGE_WEBHOOK_KEY missing' });

  const provided = readParamKey(req);
  if (!safeEqual(provided, secret)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  try {
    const record = await getLatest();
    res.json({ ok: true, topKeys: Object.keys(record || {}).slice(0, 5) });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

module.exports = router;
