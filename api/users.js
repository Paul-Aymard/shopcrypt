// =====================================================================
// api/users.js — Liste des destinataires possibles
// =====================================================================
// Route : GET /api/users
// Réponse 200 : { "users": [ { id, username, public_key }, ... ] }
// Erreurs : 401 (non connecté), 405 (mauvaise méthode)
//
// On renvoie uniquement les AUTRES utilisateurs qui ONT une clé publique :
// on ne peut chiffrer un message que pour quelqu'un qui a publié son
// "cadenas ouvert".
//
// Les clés publiques sont faites pour être partagées : les renvoyer à
// tous les utilisateurs connectés ne pose aucun problème de sécurité.
// =====================================================================

import { getSql, requireUser, sendError, allowMethods } from './_lib.js';

export default async function handler(req, res) {
  if (!allowMethods(req, res, ['GET'])) return;

  try {
    // Il faut être connecté pour voir la liste (identité tirée du jeton).
    const user = await requireUser(req, res);
    if (!user) return;

    const sql = getSql();
    // Requête paramétrée : ${user.id} est envoyé à part (pas d'injection).
    // On ne sélectionne JAMAIS password_hash : seules les colonnes utiles
    // au chiffrement sortent de la base.
    const users = await sql`
      SELECT id, username, public_key
      FROM users
      WHERE public_key IS NOT NULL
        AND id <> ${user.id}
      ORDER BY username
    `;

    return res.status(200).json({ users });
  } catch (err) {
    console.error('Erreur /api/users :', err);
    return sendError(res, 500, 'Erreur interne du serveur.');
  }
}
