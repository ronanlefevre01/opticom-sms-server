require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());

app.post('/send-sms', async (req, res) => {
  const { phoneNumber, message } = req.body;

  if (!phoneNumber || !message) {
    return res.status(400).json({ success: false, error: 'Numéro ou message manquant.' });
  }

  const formattedNumber = phoneNumber.replace(/^0/, '+33');

  const params = new URLSearchParams();
params.append('accessToken', process.env.SMSMODE_API_KEY);
params.append('message', message);
params.append('numero', formattedNumber);
params.append('emetteur', 'OPTLEFEVRE');
params.append('utf8', '1');  // ← essentiel pour déclarer l’encodage UTF‑8



  try {
    const response = await fetch('https://api.smsmode.com/http/1.6/sendSMS.do', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params,
    });

    const text = await response.text();

    console.log('📨 Réponse SMSMode :', text);

    if (response.ok && !text.includes('error')) {
      return res.json({ success: true });
    } else {
      return res.status(500).json({ success: false, error: text });
    }
  } catch (err) {
    console.error('❗ Erreur de communication avec SMSMode :', err);
    res.status(500).json({ success: false, error: 'Erreur réseau.' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur SMSMode en ligne sur http://localhost:${PORT}`);
});
