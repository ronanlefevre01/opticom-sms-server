require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { URLSearchParams } = require('url');
const GoCardless = require('gocardless-nodejs');


const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());
app.get('/', (req, res) => {
  res.send('✅ Serveur OptiCOM en ligne');
});


// === Config GoCardless ===
const gcClient = new GoCardless.Client({
  access_token: process.env.GOCARDLESS_API_KEY,
  environment: 'live', // ou 'sandbox' si vous testez
});

// === Créer un mandat GoCardless ===
app.post('/create-mandat', async (req, res) => {
  const {
    nom,
    prenom,
    email,
    adresse,
    ville,
    codePostal,
    pays,
    formule,
    siret,
    telephone
  } = req.body;

  try {
    // 🔐 Création du Redirect Flow GoCardless
    const flow = await gcClient.redirectFlows.create({
      params: {
        description: `Abonnement ${formule} - OptiCOM`,
        session_token: email + Date.now(),
        success_redirect_url: 'opticom://merci',
        prefilled_customer: {
          given_name: prenom,
          family_name: nom,
          email,
          address_line1: adresse,
          city: ville,
          postal_code: codePostal,
          country_code: pays && pays.length === 2 ? pays.toUpperCase() : 'FR',
        },
        enabled_notifications: [], // 🔕 Aucune notification automatique GoCardless
        metadata: {
          formule,
          siret,
          telephone,
        },
      },
    });

    // 🔁 Rediriger vers l’URL de signature
    res.json({ url: flow.redirect_url });
  } catch (err) {
    console.error('❗Erreur GoCardless:', err);
    res.status(500).json({ error: 'Erreur GoCardless. Veuillez réessayer.' });
  }
});


// === Envoi de SMS via SMSMode ===
app.post('/send-sms', async (req, res) => {
  const { phoneNumber, message, emetteur } = req.body;

  if (!phoneNumber || !message) {
    return res.status(400).json({ success: false, error: 'Numéro ou message manquant.' });
  }

  const formattedNumber = phoneNumber.replace(/^0/, '+33');
  const params = new URLSearchParams();
  params.append('accessToken', process.env.SMSMODE_API_KEY);
  params.append('message', message);
  params.append('numero', formattedNumber);
  params.append('emetteur', emetteur || 'Opticien');
  params.append('utf8', '1');
  params.append('charset', 'UTF-8');

  try {
    const response = await fetch('https://api.smsmode.com/http/1.6/sendSMS.do', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      },
      body: params.toString(),
    });

    const text = await response.text();
    console.log('📨 Réponse SMSMode :', text);

    if (response.ok && !text.includes('error')) {
      return res.json({ success: true });
    } else {
      return res.status(500).json({ success: false, error: text });
    }
  } catch (err) {
    console.error('❗ Erreur réseau SMSMode:', err);
    res.status(500).json({ success: false, error: 'Erreur réseau.' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur prêt sur http://localhost:${PORT}`);
});
