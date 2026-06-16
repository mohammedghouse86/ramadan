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

// 🌅 Info about fast
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

// 🕌 Info about Taraweeh prayers
app.get('/ramadan/prayers', authenticateToken, (req, res) => {
  res.json({
    prayers: ramadan.prayers,
  });
});

// 💡 Tips for Ramadan
app.get('/ramadan/tips', authenticateToken, (req, res) => {
  res.json({
    tips: ramadan.tips,
  });
});

// 💰 Zakat info
app.get('/ramadan/zakat', authenticateToken, (req, res) => {
  res.json({
    zakat: ramadan.zakat,
  });
});

app.post('/ramadan/night_of_power', authenticateToken, (req, res) => {
  const { day } = req.body;
  if (day === 27) {
    res.json({ message: `✅ Yes, ${day} is the Night of Power.` });
  } else {
    res.status(400).json({ message: `❌ No, the given day is not the Night of Power.` });
  }
});

app.post('/ramadan/fast_required', authenticateToken, (req, res) => {
  const { day } = req.body;
  if (day >= 1 && day <= 29) {
    res.json({ message: `✅ Yes, fasting is required on day ${day} of Ramadan.` });
  } else {
    res.status(400).json({ message: `❌ No, fasting is not required on this day.` });
  }
});

app.post('/ramadan/zakat_due', authenticateToken, (req, res) => {
  const { wealth } = req.body;
  if (wealth >= 3960) {
    res.json({ message: '✅ Yes, zakat is due on this amount.' });
  } else {
    res.status(400).json({ message: '❌ No, zakat is not due on this amount.' });
  }
});

app.post('/ramadan/iftar_time', authenticateToken, (req, res) => {
  const { city } = req.body;
  const times = {
    Mecca: '6:45 PM',
    Medina: '6:40 PM',
    Cairo: '6:30 PM',
    Hyderabad: '6:43 PM',
  };

  if (times[city]) {
    res.json({ message: `🕓 Iftar time in ${city} is ${times[city]}.` });
  } else {
    res.status(400).json({ message: '❌ Iftar time for the given city is not available.' });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
