require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());

app.post('/send-sms', async (req, res) => {
  const { phoneNumber, message, senderLabel } = req.body;

  if (!phoneNumber || !message) {
    return res.status(400).json({ success: false, error: 'Numéro ou message manquant.' });
  }

  const formattedNumber = phoneNumber.replace(/^0/, '+33');

  const payload = {
    recipients: [formattedNumber],
    text: message,
    sender: senderLabel || process.env.OCTOPUSH_SENDER_DEFAULT,
    type: 'sms_premium',
    purpose: 'alert',
    send_at: null,
    with_replies: false,
  };

  console.log('📦 Payload envoyé à Octopush :');
  console.log(JSON.stringify(payload, null, 2));

  try {
    const response = await fetch("https://api.octopush.com/v1/public/multi-channel/send", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "api-login": process.env.OCTOPUSH_USER_LOGIN,
    "api-key": process.env.OCTOPUSH_API_KEY,
  },
  body: JSON.stringify({
    recipients: [phoneNumber],
    text: messageText,
    sender: senderName,
    purpose: "alert",
    type: "sms_premium",
    with_replies: false,
  }),
});

    const data = await response.json();

    console.log('📬 Réponse Octopush :');
    console.log(data);
    console.log("👉 Demande d'envoi :", formattedNumber, message);
console.log("📨 Réponse Octopush :", data);
    if (response.ok && data.ticket_number) {
      return res.json({ success: true });
    } else {
      console.error('❌ Erreur Octopush :', data);
      return res.status(500).json({ success: false, error: data.message || 'Erreur lors de l’envoi.' });
    }
  } catch (err) {
    console.error('❗ Erreur réseau avec Octopush :', err);
    res.status(500).json({ success: false, error: 'Erreur de communication avec Octopush.' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur SMS démarré sur http://localhost:${PORT}`);
});
