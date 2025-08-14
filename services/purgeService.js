const cron = require('node-cron');
const { getLatest, putRecord } = require('../clients/jsonbinClient');

function monthsAgo(n){ const d=new Date(); d.setMonth(d.getMonth()-n); return d; }
function yearsAgo(n){ const d=new Date(); d.setFullYear(d.getFullYear()-n); return d; }

async function runPurge(){
  const before = await getLatest();
  const db = JSON.parse(JSON.stringify(before));

  let removedSms = 0, removedCons = 0, removedAdmin = 0;

  // 1) smsLogs: 24 mois
  if (Array.isArray(db.smsLogs)) {
    const keepAfter = monthsAgo(24);
    const initial = db.smsLogs.length;
    db.smsLogs = db.smsLogs.filter(x => new Date(x.timestamp) >= keepAfter);
    removedSms = initial - db.smsLogs.length;
  }

  // 2) consents: 3 ans + garder la DERNIÈRE décision par (licenceId|recipient)
  if (Array.isArray(db.consents)) {
    const cutoff = yearsAgo(3);
    const map = new Map();
    for (const c of db.consents) {
      const key = `${c.licenceId}|${c.recipient}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(c);
    }
    const next = [];
    for (const arr of map.values()) {
      arr.sort((a,b)=> new Date(a.timestamp) - new Date(b.timestamp));
      const last = arr[arr.length-1];
      const kept = arr.filter(x => new Date(x.timestamp) >= cutoff);
      if (!kept.includes(last)) kept.push(last);
      next.push(...kept);
    }
    removedCons = db.consents.length - next.length;
    db.consents = next;
  }

  // 3) adminLogs: 12 mois
  if (Array.isArray(db.adminLogs)) {
    const keepAfter = monthsAgo(12);
    const initial = db.adminLogs.length;
    db.adminLogs = db.adminLogs.filter(x => new Date(x.at) >= keepAfter);
    removedAdmin = initial - db.adminLogs.length;
  }

  // NE PAS toucher à: clients, licences, invoices, opticiens, optOuts, etc.
  await putRecord(db);

  // journal de l’exécution
  const log = {
    at: new Date().toISOString(),
    route: 'cron/purge',
    method: 'SYSTEM',
    status: 200,
    counts: { smsLogs: removedSms, consents: removedCons, adminLogs: removedAdmin }
  };
  const after = await getLatest();
  if (!Array.isArray(after.adminLogs)) after.adminLogs = [];
  after.adminLogs.push(log);
  await putRecord(after);

  return { ok: true, removed: log.counts };
}

function schedulePurge(){
  cron.schedule('0 3 * * *', () => { runPurge().catch(()=>{}); }, { timezone: 'Europe/Paris' });
}

module.exports = { runPurge, schedulePurge };
