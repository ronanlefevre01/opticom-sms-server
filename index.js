// index.js corrigé et amélioré
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { URLSearchParams } = require('url');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;
const GO_CARDLESS_API_BASE = 'https://api-sandbox.gocardless.com';

// Créer le dossier public/factures s'il n'existe pas
const factureDir = path.join(__dirname, 'public/factures');
if (!fs.existsSync(factureDir)) {
  fs.mkdirSync(factureDir, { recursive: true });
}

app.use(cors());
app.use(bodyParser.json());
app.use('/webhook-stripe', express.raw({ type: 'application/json' }));

// === Accueil ===
app.get('/', (req, res) => {
  res.send('✅ Serveur OptiCOM en ligne');
});

// === Créer un mandat GoCardless ===
app.post('/create-mandat', async (req, res) => {
  const {
    nom, prenom, email, adresse, ville,
    codePostal, pays, formule, siret, telephone
  } = req.body;

  try {
    const session_token = email + Date.now();

    const response = await fetch(`${GO_CARDLESS_API_BASE}/redirect_flows`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify({
        redirect_flows: {
          description: `Abonnement ${formule} - OptiCOM`,
          session_token,
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
          metadata: {
            formule, siret, telephone,
          }
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('❗ Erreur GoCardless :', data);
      return res.status(500).json({ error: 'Erreur GoCardless. Vérifiez vos infos.' });
    }

    res.json({ url: data.redirect_flows.redirect_url });

  } catch (err) {
    console.error('❗Erreur GoCardless:', err);
    res.status(500).json({ error: 'Erreur GoCardless. Veuillez réessayer.' });
  }
});

// === Confirmer un mandat GoCardless ===
app.post('/confirm-mandat', async (req, res) => {
  const { redirect_flow_id } = req.body;

  if (!redirect_flow_id) {
    return res.status(400).json({ error: 'Paramètre manquant: redirect_flow_id' });
  }

  try {
    const response = await fetch(`${GO_CARDLESS_API_BASE}/redirect_flows/${redirect_flow_id}/actions/complete`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ data: { session_token: redirect_flow_id } })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('❗Erreur GoCardless (confirmation) :', data);
      return res.status(500).json({ error: 'Échec confirmation mandat' });
    }

    const customer = data.redirect_flow.links.customer;
    const mandate = data.redirect_flow.links.mandate;
    const info = data.redirect_flow;

    const licence = {
      id: uuidv4(),
      nom: info.prefilled_customer.given_name,
      prenom: info.prefilled_customer.family_name,
      email: info.prefilled_customer.email,
      telephone: info.metadata.telephone,
      formule: info.metadata.formule,
      siret: info.metadata.siret,
      customer,
      mandate,
      credits: 0,
      createdAt: new Date().toISOString(),
    };

    const path = './licences.json';
    let licences = [];

    if (fs.existsSync(path)) {
      licences = JSON.parse(fs.readFileSync(path, 'utf-8'));
    }

    licences.push(licence);
    fs.writeFileSync(path, JSON.stringify(licences, null, 2));

    console.log('✅ Licence enregistrée:', licence.email);
    res.json({ success: true, licence });

  } catch (err) {
    console.error('❗Erreur serveur /confirm-mandat :', err);
    res.status(500).json({ error: 'Erreur réseau ou serveur' });
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

// === Achat de crédits via GoCardless (clients abonnés) ===
app.post('/achat-credits-gocardless', async (req, res) => {
  const { email, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity || '1'));

  try {
    const licences = fs.existsSync('./licences.json') ? JSON.parse(fs.readFileSync('./licences.json', 'utf-8')) : [];
    const index = licences.findIndex(l => l.email === email);

    if (index === -1) {
      return res.status(404).json({ error: "Licence introuvable" });
    }

    const mandate = licences[index].mandate;

    const response = await fetch(`${GO_CARDLESS_API_BASE}/payments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify({
        payments: {
          amount: 6 * qty * 100,
          currency: 'EUR',
          links: { mandate },
          description: `Achat ponctuel de ${qty * 100} crédits SMS - OptiCOM`,
          metadata: { email, type: 'achat-credits', quantity: qty.toString() }
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('❗ Erreur paiement GoCardless :', data);
      return res.status(500).json({ error: 'Paiement échoué' });
    }

    licences[index].credits += qty * 100;
    fs.writeFileSync('./licences.json', JSON.stringify(licences, null, 2));

    // Génération automatique de la facture PDF
    const facturePayload = {
      opticien: licences[index],
      type: 'Achat de crédits SMS (GoCardless)',
      montant: 6 * qty,
      details: `${qty * 100} crédits achetés`
    };

    fetch(`http://localhost:${PORT}/api/generate-invoice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(facturePayload)
    })
    .then(res => res.json())
    .then(data => {
      console.log(`📄 Facture générée : ${data.url}`);
    })
    .catch(err => {
      console.error('❌ Erreur génération facture GoCardless :', err);
    });

    res.json({ success: true, creditsAjoutes: qty * 100 });
  } catch (err) {
    console.error('❗ Erreur achat GoCardless :', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// === Créer une session Stripe ===
app.post('/create-checkout-session', async (req, res) => {
  const { clientEmail, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity || '1'));

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'eur',
            product_data: { name: 'Crédits SMS OptiCOM (lot de 100)' },
            unit_amount: 1700,
          },
          quantity: qty,
        },
      ],
      success_url: `opticom://merci-achat?credits=${qty * 100}`,
      cancel_url: 'opticom://annulation-achat',
      metadata: {
        email: clientEmail || '',
        quantity: qty.toString(),
      },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('❗Erreur Stripe:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la session Stripe.' });
  }
});

// === Webhook Stripe pour ajout de crédits ===
app.post('/webhook-stripe', (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('❌ Erreur de signature Stripe :', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.metadata?.email;
    const quantity = parseInt(session.metadata?.quantity || '1');

    if (!email) return res.status(200).send('OK');

    const pathLic = './licences.json';
    let licences = fs.existsSync(pathLic) ? JSON.parse(fs.readFileSync(pathLic, 'utf-8')) : [];
    const index = licences.findIndex(l => l.email === email);

    if (index !== -1) {
      licences[index].credits = (licences[index].credits || 0) + (100 * quantity);
      fs.writeFileSync(pathLic, JSON.stringify(licences, null, 2));
      console.log(`✅ ${100 * quantity} crédits ajoutés à ${email}`);

      // Génération de la facture
      const facturePayload = {
        opticien: licences[index],
        type: 'Achat de crédits SMS (Stripe)',
        montant: 17 * quantity,
        details: `${100 * quantity} crédits achetés`
      };

      fetch(`http://localhost:${PORT}/api/generate-invoice`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(facturePayload)
      })
      .then(r => r.json())
      .then(data => console.log(`📄 Facture générée : ${data.url}`))
      .catch(err => console.error('❌ Erreur facture Stripe :', err));
    }
  }

  res.status(200).send('OK');
});

// === Servir les factures et licences ===
app.use('/factures', express.static(path.join(__dirname, 'public/factures')));
app.use('/licences.json', express.static(path.join(__dirname, 'licences.json')));

// === Génération d'une facture PDF ===
app.post('/api/generate-invoice', (req, res) => {
  const { opticien, type, montant, details } = req.body;

  if (!opticien || !opticien.id) {
    return res.status(400).json({ error: 'Opticien manquant ou invalide' });
  }

  const fileName = `facture-${opticien.id}-${uuidv4()}.pdf`;
  const filePath = path.join(__dirname, 'public/factures', fileName);

  const doc = new PDFDocument();
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  doc.fontSize(20).text('📄 Facture OptiCOM', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Nom : ${opticien.nom}`);
  doc.text(`SIRET : ${opticien.siret}`);
  doc.text(`Email : ${opticien.email}`);
  doc.text(`Téléphone : ${opticien.telephone}`);
  doc.moveDown();
  doc.text(`Type de facture : ${type}`);
  doc.text(`Montant TTC : ${montant.toFixed(2)} €`);
  doc.text(`Détails : ${details}`);
  doc.text(`Date : ${new Date().toLocaleDateString('fr-FR')}`);
  doc.end();

  stream.on('finish', () => {
  try {
    const licencesPath = path.join(__dirname, 'licences.json');
    const licences = JSON.parse(fs.readFileSync(licencesPath, 'utf-8'));

    const index = licences.findIndex(l => l.id === opticien.id);
    if (index !== -1) {
      if (!licences[index].factures) {
        licences[index].factures = [];
      }

      licences[index].factures.push(fileName);
      fs.writeFileSync(licencesPath, JSON.stringify(licences, null, 2));
      console.log(`✅ Facture enregistrée dans licences.json pour ${opticien.email}`);
    } else {
      console.warn(`⚠️ Opticien ID ${opticien.id} introuvable dans licences.json`);
    }

    res.json({ url: `/factures/${fileName}` });
  } catch (err) {
    console.error('❌ Erreur mise à jour licences.json :', err);
    res.status(500).json({ error: 'PDF généré mais erreur mise à jour licences.json' });
  }
});


  stream.on('error', (err) => {
    console.error('❌ Erreur PDF :', err);
    res.status(500).json({ error: 'Erreur création PDF' });
  });
});

// === Lancement serveur ===
app.listen(PORT, () => {
  console.log(`✅ Serveur prêt sur http://localhost:${PORT}`);
});

