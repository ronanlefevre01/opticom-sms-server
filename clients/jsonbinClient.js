// clients/jsonbinClient.js
const axios = require('axios');

const BIN_ID = process.env.JSONBIN_BIN_ID;
const MASTER = process.env.JSONBIN_MASTER_KEY;

if (!BIN_ID || !MASTER) {
  throw new Error('Missing env: JSONBIN_BIN_ID or JSONBIN_MASTER_KEY');
}

const client = axios.create({
  baseURL: 'https://api.jsonbin.io/v3/b',
  headers: {
    'X-Master-Key': MASTER,
    'Content-Type': 'application/json'
  }
});

async function getLatest() {
  const { data } = await client.get(`/${BIN_ID}/latest`);
  return data.record || {};
}

async function putRecord(record) {
  const { data } = await client.put(`/${BIN_ID}`, record, {
    headers: { 'X-Bin-Versioning': 'true' }
  });
  return data;
}

module.exports = { getLatest, putRecord };
