function requireAdmin(req, res, next) {
  const hdr = req.get('authorization') || '';
  const token = hdr.replace(/^Bearer\s+/i, '').trim();
  if (!token || token !== process.env.ADMIN_UPLOAD_TOKEN) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}
module.exports = { requireAdmin };
