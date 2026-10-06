// =====================================================================
// api/keys.js — Clé PUBLIQUE de l'utilisateur connecté
// =====================================================================
// Routes :
//   GET /api/keys  -> { "public_key": "<PEM>" | null }   (ma clé actuelle)
//   PUT /api/keys  -> enregistre ma clé publique
//       Corps attendu : { "public_key": "-----BEGIN PUBLIC KEY-----..." }
//       Réponse 200   : { "ok": true }
// Erreurs : 400 (clé invalide), 401 (non connecté), 405 (mauvaise méthode)
//
// SÉCURITÉ : cette route n'accepte QUE des clés publiques. Si quelqu'un
// envoyait par erreur une clé privée, elle serait refusée (voir plus bas).
// =====================================================================

import { createPublicKey } from 'node:crypto';
import { getSql, requireUser, sendError, allowMethods, getBody } from './_lib.js';

const PEM_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_FOOTER = '-----END PUBLIC KEY-----';

export default async function handler(req, res) {
  if (!allowMethods(req, res, ['GET', 'PUT'])) return;

  try {
    // SÉCURITÉ : l'identité vient du jeton JWT, jamais du corps de la
    // requête. Impossible donc de remplacer la clé d'un autre utilisateur.
    const user = await requireUser(req, res);
    if (!user) return; // 401 déjà envoyée

    // ------------------------- GET -------------------------
    if (req.method === 'GET') {
      return res.status(200).json({ public_key: user.public_key });
    }

    // ------------------------- PUT -------------------------
    const body = getBody(req);
    if (body === null) {
      return sendError(res, 400, 'Corps de requête JSON invalide.');
    }

    const pem = String(body.public_key ?? '').trim();

    // 1) Vérification de forme : c'est bien un PEM de clé PUBLIQUE.
    // SÉCURITÉ : une clé privée commence par "-----BEGIN PRIVATE KEY-----"
    // et est donc refusée ici. Le serveur ne doit jamais en recevoir.
    if (!pem.startsWith(PEM_HEADER) || !pem.endsWith(PEM_FOOTER)) {
      return sendError(res, 400, 'Clé invalide : un PEM "PUBLIC KEY" est attendu.');
    }
    // Une clé RSA 2048 en PEM fait environ 450 caractères : on refuse
    // les textes démesurés (protection contre l'envoi de données énormes).
    if (pem.length > 1000) {
      return sendError(res, 400, 'Clé invalide : texte trop long.');
    }

    // 2) Vérification de fond : on demande à Node.js de LIRE la clé.
    // createPublicKey échoue si le contenu base64 n'est pas une vraie clé.
    let keyObject;
    try {
      keyObject = createPublicKey(pem);
    } catch {
      return sendError(res, 400, 'Clé invalide : contenu illisible.');
    }

    // 3) Respect des choix cryptographiques du projet :
    //    RSA, module de 2048 bits, exposant public 65537.
    const details = keyObject.asymmetricKeyDetails || {};
    if (keyObject.asymmetricKeyType !== 'rsa') {
      return sendError(res, 400, 'Clé invalide : seules les clés RSA sont acceptées.');
    }
    if (details.modulusLength !== 2048) {
      return sendError(res, 400, 'Clé invalide : la clé doit faire 2048 bits.');
    }
    if (details.publicExponent !== 65537n) {
      return sendError(res, 400, 'Clé invalide : l’exposant public doit être 65537.');
    }

    // 4) Enregistrement (requête paramétrée, uniquement pour MOI : user.id
    // vient du jeton). Publier une nouvelle clé remplace l'ancienne.
    const sql = getSql();
    await sql`
      UPDATE users
      SET public_key = ${pem}
      WHERE id = ${user.id}
    `;

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Erreur /api/keys :', err);
    return sendError(res, 500, 'Erreur interne du serveur.');
  }
}
