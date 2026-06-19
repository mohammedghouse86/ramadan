// app.js
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const {
  authenticateToken,
  requireAdmin,
  PRIVATE_KEY,
  JWT_ALGORITHM,
  revokeToken,
} = require('./auth');

const {
  ramadan,
  getTenant,
  findUserByName,
  findUserById,
  listUsersByTenant,
  createUser,
  deleteUser,
  publicUser,
  addAuditEntry,
  listAuditByTenant,
} = require('./data');

const app = express();
// replace: app.use(express.json());
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  express.json()(req, res, next);
});
app.use(cors());

// ===== Rate limiters =======================================================
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' },
});

app.use(globalLimiter);

// ===== Helpers =============================================================
function parseIntegerId(value) {
  if (!/^\d+$/.test(String(value))) return null;
  return parseInt(value, 10);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function parseUUID(value) {
  const s = String(value);
  return UUID_RE.test(s) ? s : null;
}

// ===========================================================================
//  AUTH — name-only, multi-tenant login
// ===========================================================================
// POST /login  { name: "admin1" }            -> logs in seeded user
// POST /login  { name: "newperson" }         -> auto-creates a user in tenant 1
// POST /login  { name: "newperson", tenantId: 2 } -> auto-create in tenant 2
app.post('/login', authLimiter, (req, res) => {
  const { name, tenantId } = req.body;

  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: 'A name is required to log in.' });
  }

  let user = findUserByName(name);

  // Unknown name -> create a regular user on the fly (no password needed).
  if (!user) {
    let tid = 1;
    if (tenantId !== undefined) {
      const parsed = parseIntegerId(tenantId);
      if (parsed === null || !getTenant(parsed)) {
        return res.status(400).json({ error: 'Invalid tenantId.' });
      }
      tid = parsed;
    }
    user = createUser({ name: String(name).trim(), role: 'user', tenantId: tid });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, role: user.role, tenantId: user.tenantId },
    PRIVATE_KEY,
    { algorithm: JWT_ALGORITHM, expiresIn: '15m', issuer: 'myapi.example.com' }
  );

  addAuditEntry({
    tenantId: user.tenantId,
    actorId: user.id,
    actorName: user.name,
    action: 'login',
  });

  res.json({
    token,
    user: publicUser(user),
    tenant: getTenant(user.tenantId)?.name,
  });
});

// ===========================================================================
//  SELF / PII
// ===========================================================================
// Your own full profile, including your PII.
app.get('/me', authenticateToken, (req, res) => {
  const me = findUserById(req.user.id);
  if (!me) return res.status(404).json({ error: 'User no longer exists.' });
  res.json({
    id: me.id,
    name: me.name,
    role: me.role,
    tenantId: me.tenantId,
    tenant: getTenant(me.tenantId)?.name,
    pii: me.pii, // 🔒 PII: returned only for yourself
  });
});

// ===========================================================================
//  RAMADAN INFO (authenticated, tenant-scoped where relevant)
// ===========================================================================
app.get('/ramadan', authenticateToken, (req, res) => {
  res.json({ month: ramadan.month, description: ramadan.description });
});

app.get('/ramadan/month', authenticateToken, (req, res) => {
  res.json({
    name: ramadan.month,
    number: ramadan.number,
    message: `${ramadan.month} is the ${ramadan.number}th month of the Islamic calendar.`,
  });
});

app.get('/ramadan/benefits', authenticateToken, (req, res) => {
  res.json({ benefits: ramadan.benefits });
});

app.get('/ramadan/fasting', authenticateToken, (req, res) => {
  res.json({ fasting: ramadan.fasting });
});

app.get('/ramadan/iftar', authenticateToken, (req, res) => {
  res.json({ iftar: ramadan.iftar });
});

app.get('/ramadan/suhoor', authenticateToken, (req, res) => {
  res.json({ suhoor: ramadan.suhoor });
});

app.get('/ramadan/prayers', authenticateToken, (req, res) => {
  res.json({ prayers: ramadan.prayers });
});

// Was previously unauthenticated — now requires a token like the rest.
app.get('/ramadan/tips', authenticateToken, (req, res) => {
  res.json({ tips: ramadan.tips });
});

app.get('/ramadan/zakat', authenticateToken, (req, res) => {
  res.json({ zakat: ramadan.zakat });
});

// ===== Ramadan utility POST endpoints ======================================
app.post('/ramadan/night_of_power', authenticateToken, (req, res) => {
  const { day } = req.body;
  if (day === 27) {
    res.json({ message: `✅ Yes, ${day} is the Night of Power.` });
  } else {
    res.status(400).json({ message: '❌ No, the given day is not the Night of Power.' });
  }
});

app.post('/ramadan/fast_required', authenticateToken, (req, res) => {
  const { day } = req.body;
  if (day >= 1 && day <= 29) {
    res.json({ message: `✅ Yes, fasting is required on day ${day} of Ramadan.` });
  } else {
    res.status(400).json({ message: '❌ No, fasting is not required on this day.' });
  }
});

// Uses the caller's tenant nisab threshold.
app.post('/ramadan/zakat_due', authenticateToken, (req, res) => {
  const { wealth } = req.body;
  const tenant = getTenant(req.user.tenantId);
  const nisab = tenant?.zakatNisab ?? 3960;
  if (wealth >= nisab) {
    res.json({ message: `✅ Yes, zakat is due (nisab for ${tenant?.name} is ${nisab}).` });
  } else {
    res.status(400).json({ message: `❌ No, zakat is not due (nisab is ${nisab}).` });
  }
});

// Iftar times are tenant-specific: tenant 1 and tenant 2 have different cities.
app.post('/ramadan/iftar_time', authenticateToken, (req, res) => {
  const { city } = req.body;
  const tenant = getTenant(req.user.tenantId);
  const times = tenant?.iftarTimes || {};

  if (times[city]) {
    res.json({ message: `🕓 Iftar time in ${city} is ${times[city]}.` });
  } else {
    res.status(400).json({
      error: `Iftar time for "${city}" is not available for ${tenant?.name}.`,
      availableCities: Object.keys(times),
    });
  }
});

// ===========================================================================
//  ADMIN-ONLY ENDPOINTS (role === 'admin', scoped to the admin's tenant)
// ===========================================================================

// List all users in your tenant — INCLUDING their PII.
app.get('/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const members = listUsersByTenant(req.user.tenantId);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const start = (page - 1) * limit;
  const paged = members.slice(start, start + limit);
  res.set('X-Total-Count', String(members.length));
  res.set('X-Page-Limit', String(limit));
  res.set('X-Current-Page', String(page));
  res.json({
    tenant: getTenant(req.user.tenantId)?.name,
    count: members.length,
    page,
    limit,
    users: paged,
  });
});

// Fetch one user by UUID (must be in your tenant). PII included.
app.get('/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = parseUUID(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'User id must be a valid UUID.' });
  }
  const user = findUserById(id);
  if (!user || user.tenantId !== req.user.tenantId) {
    return res.status(404).json({ error: 'User not found in your tenant.' });
  }
  res.json(user);
});

// Create a user in your tenant (with optional PII). Integer id auto-assigned.
app.post('/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const { name, role, pii } = req.body;
  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: 'name is required.' });
  }
  if (findUserByName(name)) {
    return res.status(409).json({ error: 'A user with that name already exists.' });
  }
  const user = createUser({
    name: String(name).trim(),
    role: role === 'admin' ? 'admin' : 'user',
    tenantId: req.user.tenantId,
    pii: pii || {},
  });
  addAuditEntry({
    tenantId: req.user.tenantId,
    actorId: req.user.id,
    actorName: req.user.name,
    action: `create_user:${user.id}`,
  });
  res.status(201).json(user);
});

// Delete a user in your tenant by UUID.
app.delete('/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = parseUUID(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'User id must be a valid UUID.' });
  }
  const user = findUserById(id);
  if (!user || user.tenantId !== req.user.tenantId) {
    return res.status(404).json({ error: 'User not found in your tenant.' });
  }
  if (user.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  deleteUser(id);
  addAuditEntry({
    tenantId: req.user.tenantId,
    actorId: req.user.id,
    actorName: req.user.name,
    action: `delete_user:${id}`,
  });
  res.json({ message: `User ${id} deleted.` });
});

// View your tenant's sensitive config (apiKey, contact, nisab, etc.).
app.get('/admin/tenant', authenticateToken, requireAdmin, (req, res) => {
  const tenant = getTenant(req.user.tenantId);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });
  res.json(tenant); // 🔒 includes apiKey + contactEmail (admin only)
});

// Tenant-scoped audit log (logins, user create/delete).
app.get('/admin/audit', authenticateToken, requireAdmin, (req, res) => {
  const entries = listAuditByTenant(req.user.tenantId);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const start = (page - 1) * limit;
  const paged = entries.slice(start, start + limit);
  res.set('X-Total-Count', String(entries.length));
  res.set('X-Page-Limit', String(limit));
  res.set('X-Current-Page', String(page));
  res.json({
    tenant: getTenant(req.user.tenantId)?.name,
    count: entries.length,
    page,
    limit,
    entries: paged,
  });
});

// ===========================================================================
//  TOKEN MANAGEMENT
// ===========================================================================
app.post('/users/revokeToken', authenticateToken, (req, res) => {
  revokeToken(req.token);
  res.json({ message: 'Token has been revoked successfully.' });
});

// ===========================================================================
//  ERROR HANDLING — keep every response JSON, never HTML
// ===========================================================================

// 404 for any unmatched route.
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Malformed JSON bodies (thrown by express.json()) land here as SyntaxError.
// Must have the 4-arg signature for Express to treat it as an error handler.
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    return res.status(400).json({ error: 'Invalid JSON in request body.' });
  }
  return next(err);
});

// Generic fallback so nothing ever returns Express's default HTML error page.
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
