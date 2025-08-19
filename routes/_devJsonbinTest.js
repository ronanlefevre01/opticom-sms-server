// routes/_devJsonbinTest.js
const express = require('express');
const router = express.Router();
const { jsonbinDataGetAll, jsonbinDataPutAll } = require('../services/jsonbinData');

router.get('/__test/jsonbin-data', async (req, res) => {
  try {
    const before = await jsonbinDataGetAll();
    const record = before.data;
    record._lastTest = new Date().toISOString(); // marqueur
    await jsonbinDataPutAll(record);
    const after = await jsonbinDataGetAll();
    res.json({ ok: true, before: before.data, after: after.data });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

module.exports = router;
