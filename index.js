require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fetch = require('node-fetch');

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

  try {
    const response = await fetch('https://api.octopush.com/v1/public/message-sms/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.OCTOPUSH_API_KEY,
        'api-login': process.env.OCTOPUSH_USER_LOGIN,
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (response.ok && data.ticket_number) {
      return res.json({ success: true });
    } else {
      console.error('Erreur Octopush :', data);
      return res.status(500).json({ success: false, error: data.message || 'Erreur lors de l’envoi.' });
    }
  } catch (err) {
    console.error('Erreur réseau :', err);
    res.status(500).json({ success: false, error: 'Erreur de communication avec Octopush.' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur SMS démarré sur http://localhost:${PORT}`);
});
