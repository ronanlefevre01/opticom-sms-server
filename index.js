require('dotenv').config(); // Charge les variables d'environnement depuis .env

const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
const redirectSessionMap = {}; // { redirectFlowId: session_token }
const goCardless = require('gocardless-nodejs');



// Chargement conditionnel de node-fetch (compatible avec ES6)
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { URLSearchParams } = require('url');

// Initialisation de l'app Express
const app = express();
const PORT = process.env.PORT || 3001;

// Configuration de Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Configuration GoCardless Sandbox (ou live si tu changes l'URL)
const GO_CARDLESS_API_BASE = 'https://api-sandbox.gocardless.com';

// === Fonctions utilitaires pour charger / enregistrer les licences ===
const pathLic = path.join(__dirname, 'licences.json');

function chargerLicences() {
  return fs.existsSync(pathLic) ? JSON.parse(fs.readFileSync(pathLic, 'utf-8')) : [];
}

function enregistrerLicences(licences) {
  fs.writeFileSync(pathLic, JSON.stringify(licences, null, 2));
}



// 📁 Créer le dossier public/factures s'il n'existe pas
const factureDir = path.join(__dirname, 'public/factures');
if (!fs.existsSync(factureDir)) {
  fs.mkdirSync(factureDir, { recursive: true });
}

// 🧩 Middleware
app.use(cors());
app.use(bodyParser.json());
app.use('/webhook-stripe', express.raw({ type: 'application/json' }));

async function enregistrerLicenceEtSync(info, customer, mandate) {
  const licence = {
    id: uuidv4(),
    opticien: {
      id: 'opt-' + Math.random().toString(36).substring(2, 10),
      nom: info.prefilled_customer.given_name,
      prenom: info.prefilled_customer.family_name,
      email: info.prefilled_customer.email,
      telephone: info.metadata.telephone,
      formule: info.metadata.formule,
      siret: info.metadata.siret,
    },
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

  try {
    await fetch('https://opti-admin.vercel.app/api/save-licence', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(licence),
    });
    console.log('📤 Licence synchronisée avec OptiAdmin');
  } catch (err) {
    console.error('❌ Erreur synchronisation licence :', err.message);
  }

  return licence;
}


// 🍪 Cookies
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// 🧪 Test serveur
app.get('/', (req, res) => {
  res.send('✅ Serveur OptiCOM en ligne');
});

// 🔐 GoCardless (mode sandbox, à passer en 'live' pour production)
const gocardless = require('gocardless-nodejs');
const gocardlessClient = gocardless(process.env.GOCARDLESS_API_KEY, 'sandbox'); // ou 'live'

// 🧭 Route de création du redirect flow GoCardless
app.get('/create-redirect-flow', async (req, res) => {
  const sessionToken = uuidv4();

  try {
    const redirectFlow = await gocardlessClient.redirectFlows.create({
      description: 'Mandat OptiCOM',
      session_token: sessionToken,
      success_redirect_url: 'https://opticom.vercel.app/confirm-mandat', // Change si besoin
    });

    // 🍪 Stocke le token dans un cookie temporaire (10 min)
    res.cookie('session_token', sessionToken, { maxAge: 10 * 60 * 1000, httpOnly: true });

    // 🔁 Redirige le navigateur vers GoCardless pour signature du mandat
    res.redirect(redirectFlow.redirect_url);
  } catch (error) {
    console.error('❌ Erreur lors de la création du redirect flow GoCardless:', error.message);
    res.status(500).send('Erreur création du redirect flow');
  }
});

// === 🔐 Créer un mandat GoCardless ===

app.post('/create-mandat', async (req, res) => {
  const {
    nom, prenom, email, adresse, ville,
    codePostal, pays, formule, siret, telephone
  } = req.body;

  try {
    const session_token = crypto.randomUUID();

    const customerData = {
      given_name: prenom?.trim(),
      family_name: nom?.trim(),
      email: email?.trim(),
      address_line1: adresse?.trim(),
      city: ville?.trim(),
      postal_code: codePostal?.trim(),
      country_code: pays && pays.length === 2 ? pays.toUpperCase() : 'FR',
    };

    const redirectFlowData = {
      redirect_flows: {
        description: `Abonnement ${formule} - OptiCOM`,
        session_token,
        success_redirect_url: "opticom://MandateValidationPage",
        prefilled_customer: customerData,
        metadata: { formule, siret, telephone }
      }
    };

    const response = await fetch(`${GO_CARDLESS_API_BASE}/redirect_flows`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify(redirectFlowData)
    });

    const data = await response.json();

    if (!response.ok || !data.redirect_flows?.redirect_url) {
      console.error('❌ Erreur GoCardless :', data.error);
      return res.status(500).json({ error: 'Erreur GoCardless. Vérifiez vos informations.' });
    }

    const redirectFlowId = data.redirect_flows.id;
    redirectSessionMap[redirectFlowId] = session_token;

    res.status(200).json({ url: data.redirect_flows.redirect_url });

  } catch (err) {
    console.error('❗ Exception GoCardless:', err);
    return res.status(500).json({ error: 'Erreur serveur GoCardless. Veuillez réessayer.' });
  }
});


app.post('/confirm-mandat', async (req, res) => {
  const { redirect_flow_id } = req.body;

  if (!redirect_flow_id) {
    return res.status(400).json({ error: 'Paramètre manquant: redirect_flow_id' });
  }

  const session_token = redirectSessionMap[redirect_flow_id];
  if (!session_token) {
    return res.status(400).send('Session token introuvable pour ce redirect flow.');
  }

  try {
    const response = await fetch(`${GO_CARDLESS_API_BASE}/redirect_flows/${redirect_flow_id}/actions/complete`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ session_token })
    });

    const data = await response.json();

    if (!response.ok || !data.redirect_flow?.links) {
      console.error('❗Erreur GoCardless (confirmation) :', data);
      return res.status(500).json({ error: 'Échec confirmation mandat GoCardless.' });
    }

    const customer = data.redirect_flow.links.customer;
    const mandate = data.redirect_flow.links.mandate;
    const info = data.redirect_flow;

    const licence = await enregistrerLicenceEtSync(info, customer, mandate);

    delete redirectSessionMap[redirect_flow_id];

    res.json({ success: true, licence });
  } catch (err) {
    console.error('❗Erreur serveur POST /confirm-mandat :', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


app.get('/validation-mandat', async (req, res) => {
  try {
    const { redirect_flow_id, session_token } = req.query;

    if (!redirect_flow_id || !session_token) {
      return res.status(400).json({ error: 'Paramètres manquants.' });
    }

    const completed = await goCardless.redirectFlows.complete(redirect_flow_id, {
      params: { session_token },
    });

    const customerId = completed.links.customer;
    const customerResponse = await goCardless.customers.find(customerId);
    const customer = customerResponse.customer;

    if (!customer) {
      return res.status(500).json({ error: 'Client GoCardless introuvable.' });
    }

    // Générer une clé d'activation unique
    const licenceKey = uuidv4();

    // Construire le chemin vers licences.json
    const licencesPath = path.join(__dirname, 'public', 'licences.json');

    // Charger les licences existantes
    let licences = [];
    if (fs.existsSync(licencesPath)) {
      licences = JSON.parse(fs.readFileSync(licencesPath, 'utf8')).licences || [];
    }

    // Créer la nouvelle licence
    const newLicence = {
      id: licenceKey,
      cle: licenceKey,
      nom: customer.family_name,
      prenom: customer.given_name,
      email: customer.email,
      formule: 'pro', // ou starter/premium selon redirect flow metadata si dispo
      creditsRestants: 300,
      renouvellement: 'mensuel',
      historique: [
        {
          date: new Date().toISOString(),
          type: 'activation',
          credits: 300,
        },
      ],
    };

    // Ajouter la licence à la liste
    licences.push(newLicence);

    // Écrire le nouveau fichier licences.json
    const newContent = { licences };
    fs.writeFileSync(licencesPath, JSON.stringify(newContent, null, 2), 'utf8');

    console.log('✅ Licence créée avec succès pour :', customer.email);

    // Renvoyer la licence au client
    res.json(newLicence);

  } catch (error) {
    console.error('❌ Erreur GET /validation-mandat :', error);
    res.status(500).json({ error: 'Erreur lors de la validation du mandat.' });
  }
});




app.post('/send-sms', async (req, res) => {
  const { phoneNumber, message, emetteur, licenceKey } = req.body;

  if (!phoneNumber || !message || !licenceKey) {
    return res.status(400).json({ success: false, error: 'Champs manquants.' });
  }

  const licences = fs.existsSync('./licences.json') ? JSON.parse(fs.readFileSync('./licences.json', 'utf-8')) : [];
  const licence = licences.find(l => l.cleLicence === licenceKey);

  if (!licence) {
    return res.status(403).json({ success: false, error: 'Licence invalide.' });
  }

  if (licence.opticien.formule !== 'Illimitée' && licence.credits < 1) {
    return res.status(403).json({ success: false, error: 'Crédits insuffisants.' });
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
      if (licence.opticien.formule !== 'Illimitée') {
        licence.credits -= 1;
        fs.writeFileSync('./licences.json', JSON.stringify(licences, null, 2));
      }

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
    const pathLicences = './licences.json';
    const licences = fs.existsSync(pathLicences)
      ? JSON.parse(fs.readFileSync(pathLicences, 'utf-8'))
      : [];

    const index = licences.findIndex(l => l.opticien?.email === email);
    if (index === -1) {
      return res.status(404).json({ error: "Licence introuvable" });
    }

    const mandate = licences[index].mandate;
    if (!mandate) {
      return res.status(400).json({ error: "Aucun mandat associé à cette licence" });
    }

    // Paiement via GoCardless
    const response = await fetch(`${GO_CARDLESS_API_BASE}/payments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GOCARDLESS_API_KEY}`,
        'GoCardless-Version': '2015-07-06'
      },
      body: JSON.stringify({
        payments: {
          amount: 6 * qty * 100, // montant en centimes
          currency: 'EUR',
          links: { mandate },
          description: `Achat ponctuel de ${qty * 100} crédits SMS - OptiCOM`,
          metadata: {
            email,
            type: 'achat-credits',
            quantity: qty.toString()
          }
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('❗ Erreur GoCardless :', JSON.stringify(data, null, 2));
      return res.status(500).json({ error: 'Échec du paiement GoCardless.' });
    }

    // Ajout des crédits
    const creditsAjoutes = qty * 100;
    licences[index].credits += creditsAjoutes;
    fs.writeFileSync(pathLicences, JSON.stringify(licences, null, 2));

    // Générer facture
    const facturePayload = {
      opticien: licences[index].opticien,
      type: 'Achat de crédits SMS (GoCardless)',
      montant: 6 * qty, // en euros
      details: `${creditsAjoutes} crédits achetés via GoCardless`
    };

    try {
      const factureResponse = await fetch(`http://localhost:${PORT}/api/generate-invoice`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(facturePayload)
      });

      const factureData = await factureResponse.json();
      console.log(`📄 Facture générée automatiquement : ${factureData.url}`);
    } catch (factureErr) {
      console.error('❌ Erreur génération facture :', factureErr);
    }

    return res.json({ success: true, creditsAjoutes });

  } catch (err) {
    console.error('❗ Erreur achat GoCardless (serveur) :', err);
    return res.status(500).json({ error: 'Erreur serveur inattendue' });
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
app.post('/webhook-stripe', express.raw({ type: 'application/json' }), async (req, res) => {
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
    const index = licences.findIndex(l => l.opticien?.email === email);

    if (index !== -1) {
      // 1. Ajouter les crédits
      const creditsAjoutes = 100 * quantity;
      licences[index].credits = (licences[index].credits || 0) + creditsAjoutes;

      // 2. Générer la facture
      const facturePayload = {
        opticien: licences[index].opticien,
        type: 'Achat de crédits SMS (Stripe)',
        montant: 17 * quantity,
        details: `${creditsAjoutes} crédits achetés`
      };

      try {
        const response = await fetch(`http://localhost:${PORT}/api/generate-invoice`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(facturePayload),
        });

        const data = await response.json();

        // 3. Sauvegarder le lien de la facture dans la licence
        if (!licences[index].factures) licences[index].factures = [];
        licences[index].factures.push({
          date: new Date().toISOString(),
          url: data.url,
          type: 'Stripe',
          montant: 17 * quantity,
          credits: creditsAjoutes
        });

        fs.writeFileSync(pathLic, JSON.stringify(licences, null, 2));
        console.log(`✅ ${creditsAjoutes} crédits ajoutés + facture générée pour ${email}`);
      } catch (err) {
        console.error('❌ Erreur génération facture Stripe :', err);
      }
    }
  }

  res.status(200).send('OK');
});

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

      const index = licences.findIndex(l => l.opticien?.id === opticien.id);
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

app.post('/send-transactional', async (req, res) => {
  const { phoneNumber, message, senderLabel, opticienId } = req.body;

  if (!opticienId) return res.status(400).json({ success: false, error: 'Opticien ID manquant' });

  const licences = chargerLicences();
  const index = licences.findIndex(l => l.opticien?.id === opticienId);

  if (index === -1) return res.status(404).json({ success: false, error: 'Licence introuvable' });

  if ((licences[index].credits || 0) <= 0) {
    return res.status(403).json({ success: false, error: 'Crédits épuisés' });
  }

  try {
    const response = await axios.post(
      'https://api.smsmode.com/http/1.6/sendSMS.do',
      null,
      {
        params: {
          accessToken: process.env.SMSMODE_API_KEY,
          message,
          numero: phoneNumber.replace(/^0/, '+33'),
          emetteur: senderLabel || 'Opticien',
        },
      }
    );

    // Décrémenter 1 crédit
    licences[index].credits -= 1;
    enregistrerLicences(licences);

    res.json({ success: true, data: response.data });
  } catch (error) {
    console.error('Erreur SMS transactionnel :', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/send-promotional', async (req, res) => {
  const { phoneNumber, message, senderLabel, opticienId } = req.body;

  if (!opticienId) return res.status(400).json({ success: false, error: 'Opticien ID manquant' });

  const licences = chargerLicences();
  const index = licences.findIndex(l => l.opticien?.id === opticienId);

  if (index === -1) return res.status(404).json({ success: false, error: 'Licence introuvable' });

  if ((licences[index].credits || 0) <= 0) {
    return res.status(403).json({ success: false, error: 'Crédits épuisés' });
  }

  try {
    const response = await axios.post(
      'https://api.smsmode.com/http/1.6/sendMarketingSMS.do',
      null,
      {
        params: {
          accessToken: process.env.SMSMODE_API_KEY,
          message,
          numero: phoneNumber.replace(/^0/, '+33'),
          emetteur: senderLabel || 'Opticien',
        },
      }
    );

    // Décrémenter 1 crédit
    licences[index].credits -= 1;
    enregistrerLicences(licences);

    res.json({ success: true, data: response.data });
  } catch (error) {
    console.error('Erreur SMS promotionnel :', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});


// === Récupérer les crédits restants d’un opticien ===
app.get('/api/credits/:opticienId', (req, res) => {
  const { opticienId } = req.params;

  if (!opticienId) {
    return res.status(400).json({ error: 'ID opticien manquant.' });
  }

  const pathLic = path.join(__dirname, 'licences.json');
  if (!fs.existsSync(pathLic)) {
    return res.status(500).json({ error: 'Fichier licences.json introuvable.' });
  }

  const licences = JSON.parse(fs.readFileSync(pathLic, 'utf-8'));
  const licence = licences.find(l => l.opticien?.id === opticienId);

  if (!licence) {
    return res.status(404).json({ error: 'Opticien introuvable.' });
  }

  res.json({ credits: licence.credits || 0 });
});



// === Lancement serveur ===
app.listen(PORT, () => {
  console.log(`✅ Serveur prêt sur http://localhost:${PORT}`);
});

