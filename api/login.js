// =====================================================================
// api/login.js — Connexion d'un utilisateur existant
// =====================================================================
// Route : POST /api/login
// Corps attendu (JSON) : { "username": "awa", "password": "motdepasse123" }
// Réponse 200 : { "token": "<JWT>", "user": { id, username, has_public_key } }
// Erreurs : 400 (champs manquants), 401 (identifiants incorrects),
//           405 (mauvaise méthode), 500 (erreur serveur)
// =====================================================================

import bcrypt from 'bcryptjs';
import { getSql, signToken, sendError, allowMethods, getBody } from './_lib.js';

// SÉCURITÉ : haché "leurre", calculé une seule fois au démarrage.
// Si le pseudo n'existe pas, on compare quand même le mot de passe avec
// ce leurre. Ainsi la réponse prend le même temps (~0,1 s) que le pseudo
// existe ou non : un attaquant ne peut pas deviner quels pseudos existent
// en mesurant le temps de réponse (attaque "temporelle").
const DUMMY_HASH = bcrypt.hashSync('leurre-pour-egaliser-le-temps', 10);

export default async function handler(req, res) {
  // Seule la méthode POST est acceptée (le mot de passe ne doit jamais
  // passer dans l'URL, ce qui arriverait avec GET).
  if (!allowMethods(req, res, ['POST'])) return;

  try {
    // 1) Lecture et vérification minimale du corps
    const body = getBody(req);
    if (body === null) {
      return sendError(res, 400, 'Corps de requête JSON invalide.');
    }

    const username = String(body.username ?? '').trim();
    const password = String(body.password ?? '');

    if (!username || !password) {
      return sendError(res, 400, 'Pseudo et mot de passe obligatoires.');
    }

    // 2) Recherche de l'utilisateur (requête paramétrée)
    const sql = getSql();
    const rows = await sql`
      SELECT id, username, password_hash, public_key
      FROM users
      WHERE username = ${username}
    `;
    const user = rows[0];

    // 3) Vérification du mot de passe
    // SÉCURITÉ : bcrypt.compare relit le sel et le coût stockés dans le
    // haché, re-hache le mot de passe saisi avec ce même sel, puis compare
    // les deux résultats. Le mot de passe d'origine n'est jamais "déchiffré"
    // (c'est impossible : un hachage est à sens unique).
    const passwordOk = await bcrypt.compare(
      password,
      user ? user.password_hash : DUMMY_HASH
    );

    // SÉCURITÉ : même message d'erreur que le pseudo soit inconnu ou que
    // le mot de passe soit faux. On ne dit pas à un attaquant lequel des
    // deux est correct (sinon il pourrait d'abord trouver les pseudos).
    if (!user || !passwordOk) {
      return sendError(res, 401, 'Pseudo ou mot de passe incorrect.');
    }

    // 4) Succès : on délivre le jeton JWT.
    // has_public_key indique au front s'il faut proposer de générer
    // la paire de clés RSA (page keys.html).
    return res.status(200).json({
      token: signToken(user),
      user: {
        id: user.id,
        username: user.username,
        has_public_key: user.public_key !== null,
      },
    });
  } catch (err) {
    console.error('Erreur /api/login :', err);
    return sendError(res, 500, 'Erreur interne du serveur.');
  }
}
