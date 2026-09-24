// auth.js
const jwt = require('jsonwebtoken');

// In a real app, load this from an env var. Kept inline to stay lightweight.
const SECRET = process.env.JWT_SECRET || 'your-256-bit-secret-password-password';

const tokenBlacklist = new Set();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Missing authorization token.' });
  }

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token has been revoked.' });
  }

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      // Distinguish "expired" (401, re-login) from "invalid/tampered" (403).
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired, please log in again.' });
      }
      return res.status(403).json({ error: 'Invalid token.' });
    }
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

// Gate for endpoints restricted to admin1 specifically (not just any admin).
// Must run AFTER authenticateToken.
function requireAdmin1(req, res, next) {
  const u = req.user;
  if (!u || u.name !== 'admin1' || u.role !== 'admin' || u.tenantId !== 1) {
    return res.status(403).json({ error: '⛔ Restricted to admin1.' });
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
  requireAdmin1,
  SECRET,
  revokeToken,
  isTokenRevoked,
};
