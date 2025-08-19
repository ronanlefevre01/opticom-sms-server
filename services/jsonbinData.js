// helpers/jsonbinData.js
const DATA_BIN_ID = process.env.OPTICOM_DATA_BIN_ID;
const JSONBIN_KEY = process.env.JSONBIN_API_KEY;

// Garde-fou
function assertEnv() {
  if (!DATA_BIN_ID) throw new Error('OPTICOM_DATA_BIN_ID manquant (env).');
  if (!JSONBIN_KEY) throw new Error('JSONBIN_API_KEY manquant (env).');
}

// GET intégral du bin (dernière version)
async function jsonbinDataGetAll() {
  assertEnv();
  const r = await fetch(`https://api.jsonbin.io/v3/b/${DATA_BIN_ID}/latest`, {
    headers: { 'X-Master-Key': JSONBIN_KEY }
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`JSONBin data get failed: ${r.status} ${text}`);
  }
  const j = await r.json();
  const record = j.record || {};
  if (!record.licences) record.licences = {};
  return { data: record, metadata: j.metadata };
}

// Remplacement complet du record (PUT)
async function jsonbinDataPutAll(newRecord) {
  assertEnv();
  const body = JSON.stringify({
    licences: newRecord?.licences || {}
  });

  const r = await fetch(`https://api.jsonbin.io/v3/b/${DATA_BIN_ID}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-Master-Key': JSONBIN_KEY
    },
    body
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`JSONBin data put failed: ${r.status} ${text}`);
  }
  return await r.json();
}

module.exports = { jsonbinDataGetAll, jsonbinDataPutAll };
