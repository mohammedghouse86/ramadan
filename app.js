// app.js
const express = require('express');
const jwt = require('jsonwebtoken');
const { authenticateToken, SECRET } = require('./auth');
const { ramadan } = require('./data');
const cors = require('cors');


const app = express();
app.use(express.json());
app.use(cors());
// 🔐 Mock login for token
// app.post('/login', (req, res) => {
//   const { username } = req.body;
//   const user = { name: username || 'guest' };
//   const token = jwt.sign(user, SECRET, { expiresIn: '1h' });
//   res.json({ token });
// });
// app.js
app.post('/login', (req, res) => {
  const { username } = req.body;
  const user = { name: username || 'guest' };

  const token = jwt.sign(user, SECRET, {
    expiresIn: '1h',
    issuer: 'myapi.example.com' // <-- Add issuer here
  });

  res.json({ token });
});
// 📖 General info
app.get('/ramadan', authenticateToken, (req, res) => {
  res.json({
    month: ramadan.month,
    description: ramadan.description,
  });
});

// 📅 Which month is Ramadan?
app.get('/ramadan/month', authenticateToken, (req, res) => {
  res.json({
    name: ramadan.month,
    number: ramadan.number,
    message: `${ramadan.month} is the ${ramadan.number}th month of the Islamic calendar.`,
  });
});

// 🌟 Benefits of Ramadan
app.get('/ramadan/benefits', authenticateToken, (req, res) => {
  res.json({
    benefits: ramadan.benefits,
  });
});

// 🌅 Info about fasting
app.get('/ramadan/fasting', authenticateToken, (req, res) => {
  res.json({
    fasting: ramadan.fasting,
  });
});

// 🌇 Info about Iftar
app.get('/ramadan/iftar', authenticateToken, (req, res) => {
  res.json({
    iftar: ramadan.iftar,
  });
});

// 🌄 Info about Suhoor
app.get('/ramadan/suhoor', authenticateToken, (req, res) => {
  res.json({
    suhoor: ramadan.suhoor,
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
