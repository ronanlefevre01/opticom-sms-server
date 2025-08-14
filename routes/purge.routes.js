const express = require('express');
const router = express.Router();
const { runPurge } = require('../services/purgeService');
const { requireAdmin } = require('../middleware/adminAuth');

router.post('/internal/purge', requireAdmin, async (req, res) => {
  try { const out = await runPurge(); res.json(out); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
