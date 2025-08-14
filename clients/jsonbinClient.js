// clients/jsonbinClient.js
const axios = require('axios');

// Supporte plusieurs noms de variables d'env (compat)
const BIN_ID =
  process.env.JSONBIN_BIN_ID || process.env.JSON_BIN_ID;

const MASTER =
  process.env.JSONBIN_MASTER_KEY || process.env.JSONBIN_API_KEY; // <— compat Render

const ACCESS =
  process.env.JSONBIN_ACCESS_KEY || process.env.JSONBIN_READ_KEY || '';

if (!BIN_ID || !MASTER) {
  throw new Error(
    'Missing env: JSONBIN_BIN_ID and one of JSONBIN_MASTER_KEY or JSONBIN_API_KEY'
  );
}

const client = axios.create({
  baseURL: 'https://api.jsonbin.io/v3/b',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'X-Master-Key': MASTER,
    ...(ACCESS ? { 'X-Access-Key': ACCESS } : {})
  }
});

async function getLatest() {
  const { data } = await client.get(`/${BIN_ID}/latest`);
  return data && data.record ? data.record : {};
}

async function putRecord(record) {
  const { data } = await client.put(`/${BIN_ID}`, record, {
    headers: { 'X-Bin-Versioning': 'true' }
  });
  return data;
}

module.exports = { getLatest, putRecord };
