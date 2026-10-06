// =====================================================================
// api/messages.js — Envoi et réception des messages CHIFFRÉS
// =====================================================================
// Routes :
//   POST /api/messages
//       Corps : { "recipient_id": "<uuid>", "ciphertext": "<base64>" }
//       Réponse 201 : { "id": "<uuid>", "created_at": "..." }
//   GET /api/messages
//       Réponse 200 : { "messages": [ { id, sender_username, ciphertext, created_at } ] }
// Erreurs : 400 (données invalides), 401 (non connecté),
//           403 (action interdite), 404 (destinataire introuvable), 405
//
// IMPORTANT : le serveur ne reçoit et ne renvoie QUE du texte chiffré.
// Il ne peut pas lire les messages : il n'a aucune clé privée.
// =====================================================================

import { getSql, requireUser, sendError, allowMethods, getBody } from './_lib.js';

// Format d'un UUID : 8-4-4-4-12 caractères hexadécimaux.
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// CRYPTO : un chiffré RSA-OAEP 2048 bits fait toujours 256 octets,
// soit exactement 344 caractères en base64 (dont un "=" final).
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;
const CIPHERTEXT_LENGTH = 344;

export default async function handler(req, res) {
  if (!allowMethods(req, res, ['GET', 'POST'])) return;

  try {
    // SÉCURITÉ : l'utilisateur connecté vient du JWT. On ne lit JAMAIS un
    // "sender_id" dans le corps : impossible d'envoyer au nom d'un autre.
    const user = await requireUser(req, res);
    if (!user) return;

    const sql = getSql();

    // ======================= GET : mes messages reçus =======================
    if (req.method === 'GET') {
      // SÉCURITÉ : filtre "recipient_id = moi" => chacun ne voit que SES
      // messages. JOIN pour récupérer le pseudo de l'expéditeur.
      const messages = await sql`
        SELECT m.id,
               s.username AS sender_username,
               m.ciphertext,
               m.created_at
        FROM messages m
        JOIN users s ON s.id = m.sender_id
        WHERE m.recipient_id = ${user.id}
        ORDER BY m.created_at DESC
        LIMIT 100
      `;
      return res.status(200).json({ messages });
    }

    // ======================= POST : envoyer un message =======================
    const body = getBody(req);
    if (body === null) {
      return sendError(res, 400, 'Corps de requête JSON invalide.');
    }

    const recipientId = String(body.recipient_id ?? '').trim();
    const ciphertext = String(body.ciphertext ?? '').trim();

    // 1) Le destinataire doit être un identifiant bien formé.
    if (!UUID_REGEX.test(recipientId)) {
      return sendError(res, 400, 'Destinataire invalide.');
    }

    // 2) On refuse de s'écrire à soi-même (même règle que la base de données).
    if (recipientId === user.id) {
      return sendError(res, 403, 'Vous ne pouvez pas vous envoyer un message à vous-même.');
    }

    // 3) Le "chiffré" doit avoir la forme d'un vrai chiffré RSA-2048 en base64.
    // SÉCURITÉ : cela empêche (par erreur ou par malice) d'enregistrer un
    // message EN CLAIR à la place d'un message chiffré.
    if (ciphertext.length !== CIPHERTEXT_LENGTH || !BASE64_REGEX.test(ciphertext)) {
      return sendError(
        res,
        400,
        'Chiffré invalide : 344 caractères base64 attendus (RSA-OAEP 2048 bits).'
      );
    }
    if (Buffer.from(ciphertext, 'base64').length !== 256) {
      return sendError(res, 400, 'Chiffré invalide : 256 octets attendus.');
    }

    // 4) Le destinataire doit exister ET avoir publié une clé publique.
    const recipients = await sql`
      SELECT id, public_key
      FROM users
      WHERE id = ${recipientId}
    `;
    if (recipients.length === 0) {
      return sendError(res, 404, 'Destinataire introuvable.');
    }
    if (!recipients[0].public_key) {
      return sendError(res, 400, 'Ce destinataire n’a pas encore publié de clé publique.');
    }

    // 5) Enregistrement. sender_id = l'utilisateur du JETON (jamais du corps).
    const rows = await sql`
      INSERT INTO messages (sender_id, recipient_id, ciphertext)
      VALUES (${user.id}, ${recipientId}, ${ciphertext})
      RETURNING id, created_at
    `;

    return res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Erreur /api/messages :', err);
    return sendError(res, 500, 'Erreur interne du serveur.');
  }
}
