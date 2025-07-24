const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

function genererFacturePDF(opticien, infosFacture) {
  const doc = new PDFDocument();
  const nomFichier = `facture-${Date.now()}.pdf`;
  const cheminFichier = path.join(__dirname, '../factures', nomFichier);
  const stream = fs.createWriteStream(cheminFichier);

  doc.pipe(stream);

  doc.fontSize(20).text('Facture OptiCOM', { align: 'center' });
  doc.moveDown();

  doc.fontSize(12).text(`Client : ${opticien.nom} ${opticien.prenom}`);
  doc.text(`Email : ${opticien.email}`);
  doc.text(`Téléphone : ${opticien.telephone}`);
  doc.text(`SIRET : ${opticien.siret}`);
  doc.moveDown();

  doc.text(`Date : ${infosFacture.date}`);
  doc.text(`Type : ${infosFacture.type}`);
  doc.text(`Montant : ${infosFacture.montant.toFixed(2)} €`);

  doc.end();

  return new Promise((resolve, reject) => {
    stream.on('finish', () => resolve(`/factures/${nomFichier}`));
    stream.on('error', reject);
  });
}

module.exports = genererFacturePDF;
