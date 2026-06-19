// auth.js
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, 'public.pem'), 'utf8');
const JWT_ALGORITHM = 'RS256';

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

  jwt.verify(token, PUBLIC_KEY, { algorithms: [JWT_ALGORITHM] }, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired, please log in again.' });
      }
      return res.status(403).json({ error: 'Invalid token.' });
    }

    const { findUserById } = require('./data');
    const currentUser = findUserById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({ error: 'User no longer exists.' });
    }
    if (currentUser.role !== decoded.role || currentUser.tenantId !== decoded.tenantId) {
      return res.status(401).json({ error: 'Token claims are stale, please log in again.' });
    }

    req.user = decoded;
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
  PRIVATE_KEY,
  PUBLIC_KEY,
  JWT_ALGORITHM,
  revokeToken,
  isTokenRevoked,
};
