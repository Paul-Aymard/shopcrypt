// =====================================================================
// api/register.js — Inscription d'un nouvel utilisateur
// =====================================================================
// Route : POST /api/register
// Corps attendu (JSON) : { "username": "awa", "password": "motdepasse123" }
// Réponse 201 : { "token": "<JWT>", "user": { id, username, has_public_key } }
// Erreurs : 400 (données invalides), 405 (mauvaise méthode),
//           409 (pseudo déjà pris), 500 (erreur serveur)
// =====================================================================

import bcrypt from 'bcryptjs';
import { getSql, signToken, sendError, allowMethods, getBody } from './_lib.js';

// SÉCURITÉ : "coût" de bcrypt. 10 signifie 2^10 = 1024 tours de calcul.
// Chaque +1 double le temps de hachage : assez lent pour décourager
// un attaquant qui teste des milliards de mots de passe, assez rapide
// (environ 0,1 s) pour qu'un vrai utilisateur ne le remarque pas.
const BCRYPT_COST = 10;

// Pseudo : 3 à 30 caractères, lettres sans accent, chiffres, point, tiret, souligné.
const USERNAME_REGEX = /^[a-zA-Z0-9_.-]{3,30}$/;

export default async function handler(req, res) {
  // Seule la méthode POST est acceptée (on CRÉE un compte).
  if (!allowMethods(req, res, ['POST'])) return;

  try {
    // 1) Lecture du corps de la requête
    const body = getBody(req);
    if (body === null) {
      return sendError(res, 400, 'Corps de requête JSON invalide.');
    }

    // On convertit en texte et on enlève les espaces autour du pseudo.
    const username = String(body.username ?? '').trim();
    const password = String(body.password ?? '');

    // 2) Validation des données (règle : ne jamais faire confiance au client)
    if (!USERNAME_REGEX.test(username)) {
      return sendError(
        res,
        400,
        'Pseudo invalide : 3 à 30 caractères (lettres, chiffres, . _ -).'
      );
    }
    if (password.length < 8) {
      return sendError(res, 400, 'Mot de passe trop court : 8 caractères minimum.');
    }
    // SÉCURITÉ : bcrypt n'utilise que les 72 PREMIERS octets du mot de
    // passe et ignore la suite. On refuse donc les mots de passe plus
    // longs pour éviter une fausse impression de sécurité.
    if (Buffer.byteLength(password, 'utf8') > 72) {
      return sendError(res, 400, 'Mot de passe trop long : 72 octets maximum.');
    }

    // 3) Hachage du mot de passe
    // SÉCURITÉ : bcrypt ajoute automatiquement un "sel" (16 octets
    // aléatoires) avant de hacher. Deux personnes avec le même mot de
    // passe obtiennent donc deux hachés différents, et les "tables
    // arc-en-ciel" (hachés pré-calculés) deviennent inutiles.
    // Le sel et le coût sont stockés DANS le haché lui-même :
    //   $2b$10$<sel de 22 caractères><haché de 31 caractères>
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    // 4) Insertion en base
    const sql = getSql();
    // SÉCURITÉ : requête paramétrée, ${username} et ${passwordHash} sont
    // envoyés séparément du texte SQL (pas d'injection possible).
    // ON CONFLICT DO NOTHING : si le pseudo existe déjà (contrainte
    // UNIQUE), PostgreSQL n'insère rien et RETURNING renvoie 0 ligne.
    const rows = await sql`
      INSERT INTO users (username, password_hash)
      VALUES (${username}, ${passwordHash})
      ON CONFLICT (username) DO NOTHING
      RETURNING id, username
    `;

    if (rows.length === 0) {
      return sendError(res, 409, 'Ce pseudo est déjà utilisé.');
    }

    const user = rows[0];

    // 5) Connexion automatique : on renvoie directement un jeton JWT.
    // SÉCURITÉ : on ne renvoie JAMAIS password_hash au navigateur.
    return res.status(201).json({
      token: signToken(user),
      user: { id: user.id, username: user.username, has_public_key: false },
    });
  } catch (err) {
    // On affiche le détail dans les logs du serveur (visibles sur Vercel)
    // mais on renvoie un message générique au client : SÉCURITÉ, on ne
    // révèle pas le fonctionnement interne à un éventuel attaquant.
    console.error('Erreur /api/register :', err);
    return sendError(res, 500, 'Erreur interne du serveur.');
  }
}
