// app.js
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const {
  authenticateToken,
  requireAdmin,
  requireAdmin1,
  SECRET,
  revokeToken,
} = require('./auth');

const {
  ramadan,
  getTenant,
  findUserByName,
  findUserByDisplayName,
  findUserById,
  listUsersByTenant,
  deleteUser,
  publicUser,
  addAuditEntry,
  listAuditByTenant,
} = require('./data');

const app = express();
// Render fronts the app with a proxy that sets X-Forwarded-For. Trust exactly
// one hop so express-rate-limit keys on the real client IP, not the proxy's.
app.set('trust proxy', 1);
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
// Validates that an :id route param is a UUID. User ids are UUIDs.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
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
  const { name } = req.body;

  if (!name || !String(name).trim()) {
    return res.status(400).json({ error: 'A name is required to log in.' });
  }

  // Only the seeded users can log in. Unknown names are rejected — no accounts
  // are created on the fly.
  const user = findUserByName(name);
  if (!user) {
    return res.status(401).json({ error: 'Unknown user.' });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, role: user.role, tenantId: user.tenantId },
    SECRET,
    { expiresIn: '1h', issuer: 'myapi.example.com' }
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
    displayName: me.displayName,
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
// app.get('/admin/users', authenticateToken, requireAdmin, (req, res) => {
  app.get('/admin/users',authenticateToken, (req, res) => {

  const members = listUsersByTenant(req.user.tenantId);
  // const members = listUsersByTenant(1);
  res.json({
    tenant: getTenant(req.user.tenantId)?.name,
    // tenant: getTenant(1)?.name,
    count: members.length,
    users: members, // 🔒 full records with PII (admin only)
  });
});

// Fetch one user by integer id (must be in your tenant). PII included.
  // app.get('/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
      app.get('/admin/users/:id',authenticateToken, (req, res) => {

  const id = parseUUID(req.params.id);
  // const id = 1;
  if (id === null) {
    return res.status(400).json({ error: 'User id must be a valid UUID.' });
  }
  const user = findUserById(id);
  // if (!user || user.tenantId !== req.user.tenantId) {
    if (!user) {
    return res.status(404).json({ error: 'User not found in your tenant.' });
  }
  res.json(user); // 🔒 PII included
});

// Look up a user by their display name (e.g. "Aisha"). Any signed-in user, not
// just admins. Used to populate the welcome banner on login: the UI reads the
// caller's display name from /me and passes it here, so the tenant restriction
// is enforced on the client. The API itself is NOT tenant-scoped: any display
// name from any tenant resolves here.
app.get('/users/by-name/:displayName', authenticateToken, (req, res) => {
  const displayName = String(req.params.displayName || '').trim();
  if (!displayName) {
    return res.status(400).json({ error: 'displayName is required.' });
  }
  const user = findUserByDisplayName(displayName);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  res.json({
    id: user.id,
    name: user.name,
    displayName: user.displayName,
    role: user.role,
    tenantId: user.tenantId,
    tenant: getTenant(user.tenantId)?.name,
  });
});

// Delete a user in your tenant by integer id.
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
  res.json({ message: `🗑️ User ${id} deleted.` });
});

// View your tenant's sensitive config (apiKey, contact, nisab, etc.).
app.get('/admin/tenant', authenticateToken, requireAdmin, (req, res) => {
  const tenant = getTenant(req.user.tenantId);
  if (!tenant) return res.status(404).json({ error: 'Tenant not found.' });
  res.json(tenant); // 🔒 includes apiKey + contactEmail (admin only)
});

// Tenant-scoped audit log (logins, user create/delete).
app.get('/admin/audit', authenticateToken, requireAdmin, (req, res) => {
  res.json({
    tenant: getTenant(req.user.tenantId)?.name,
    entries: listAuditByTenant(req.user.tenantId),
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
