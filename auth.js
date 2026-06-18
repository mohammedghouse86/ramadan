// auth.js
const jwt = require('jsonwebtoken');

// In a real app, load this from an env var. Kept inline to stay lightweight.
const SECRET = 'your-256-bit-secret-password-password';

const tokenBlacklist = new Set();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  if (tokenBlacklist.has(token)) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    // user = decoded payload: { id, name, role, tenantId, iat, exp }
    req.user = user;
    req.token = token;
    next();
  });
}

// Gate for admin-only endpoints. Must run AFTER authenticateToken.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: '⛔ Admin access required.' });
  }
  next();
}

function revokeToken(token) {
  tokenBlacklist.add(token);
}

function isTokenRevoked(token) {
  return tokenBlacklist.has(token);
}

module.exports = {
  authenticateToken,
  requireAdmin,
  SECRET,
  revokeToken,
  isTokenRevoked,
};
