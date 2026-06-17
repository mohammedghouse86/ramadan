// auth.js
const jwt = require('jsonwebtoken');

const SECRET = 'your-256-bit-secret-password-password';

const tokenBlacklist = new Set();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  if (tokenBlacklist.has(token)) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    req.token = token;
    next();
  });
}

function revokeToken(token) {
  tokenBlacklist.add(token);
}

function isTokenRevoked(token) {
  return tokenBlacklist.has(token);
}

module.exports = { authenticateToken, SECRET, revokeToken, isTokenRevoked };
