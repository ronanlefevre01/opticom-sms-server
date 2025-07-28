import AsyncStorage from '@react-native-async-storage/async-storage';
import { Alert } from 'react-native';

const API_PROMOTIONNELLE = 'https://opticom-sms-server.onrender.com/api/send-sms-promo';
const API_TRANSACTIONNELLE = 'https://opticom-sms-server.onrender.com/api/send-sms';

type Client = {
  id: string;
  prenom: string;
  nom: string;
  telephone: string;
  consentementMarketing?: boolean;
};

export const sendSMS = async (
  clientsToSend: Client[],
  type: 'promo' | 'standard',
  messageTemplate: string
): Promise<{ successCount: number }> => {
  try {
    const licenceData = await AsyncStorage.getItem('licence');
    const licence = licenceData ? JSON.parse(licenceData) : null;
    const senderLabel = licence?.libelleExpediteur || 'OptiCOM';

    let successCount = 0;

    for (const client of clientsToSend) {
      // Ne pas envoyer aux clients non consentants si promo
      if (type === 'promo' && !client.consentementMarketing) continue;

      const message = messageTemplate
        .replace('{prenom}', client.prenom || '')
        .replace('{nom}', client.nom || '');

      const endpoint = type === 'promo' ? API_PROMOTIONNELLE : API_TRANSACTIONNELLE;

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          phoneNumber: client.telephone,
          message,
          senderLabel,
          ...(type === 'promo' ? { stop: true } : {}), // Ajoute stop=true uniquement si promo
        }),
      });

      const data = await response.json();

      if (data.success) {
        successCount++;
      } else {
        console.warn(`Échec d'envoi à ${client.telephone} : ${data.error}`);
      }
    }

    return { successCount };
  } catch (error) {
    console.error('Erreur envoi SMS :', error);
    Alert.alert('Erreur', "Une erreur est survenue lors de l'envoi des SMS.");
    return { successCount: 0 };
  }
};
