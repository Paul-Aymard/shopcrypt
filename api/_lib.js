// =====================================================================
// api/_lib.js — Outils partagés par toutes les fonctions de l'API
// =====================================================================
// Le "_" au début du nom est important : Vercel ne transforme PAS ce
// fichier en route publique (/api/_lib n'existe pas). C'est seulement
// une "boîte à outils" importée par register.js, login.js, keys.js...
//
// Contenu :
//   - getSql()      : connexion à la base Neon
//   - signToken()   : fabrique un jeton JWT après connexion
//   - requireUser() : vérifie le JWT et renvoie l'utilisateur connecté
//   - sendError()   : renvoie une erreur JSON claire
//   - getBody()     : lit le corps JSON de la requête sans planter
//   - allowMethods(): refuse les méthodes HTTP non prévues
// =====================================================================

import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';

// ---------------------------------------------------------------------
// Connexion à la base de données
// ---------------------------------------------------------------------
// On garde la connexion dans une variable pour la réutiliser entre deux
// requêtes (Vercel réutilise souvent la même instance de la fonction).
let sqlClient = null;

export function getSql() {
  if (!sqlClient) {
    // SÉCURITÉ : l'adresse de la base (qui contient son mot de passe)
    // vient d'une variable d'environnement, jamais du code source.
    const url = process.env.DATABASE_URL;
    if (!url) {
      throw new Error('DATABASE_URL manquante : remplissez le fichier .env (modèle : .env.example).');
    }
    // neon() renvoie une fonction "sql" utilisable ainsi :
    //   await sql`SELECT * FROM users WHERE id = ${id}`
    // SÉCURITÉ : avec cette écriture (gabarit étiqueté), ${id} n'est PAS
    // collé dans le texte SQL : il est envoyé à part comme PARAMÈTRE
    // ($1, $2...). Une injection SQL est donc impossible.
    sqlClient = neon(url);
  }
  return sqlClient;
}

// ---------------------------------------------------------------------
// Lecture du secret JWT
// ---------------------------------------------------------------------
function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  // SÉCURITÉ : un secret court se devine par force brute. On exige au
  // moins 32 caractères, sinon on refuse de démarrer.
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET manquant ou trop court (32 caractères minimum).');
  }
  return secret;
}

// ---------------------------------------------------------------------
// Création d'un jeton JWT (appelée par register.js et login.js)
// ---------------------------------------------------------------------
export function signToken(user) {
  return jwt.sign(
    // Contenu du jeton ("payload") : qui est l'utilisateur.
    // "sub" (subject) = l'identifiant de l'utilisateur, nom standard.
    // SÉCURITÉ : le payload est seulement encodé en base64, PAS chiffré.
    // N'importe qui peut le lire : on n'y met donc rien de secret.
    { sub: user.id, username: user.username },
    // SÉCURITÉ : la signature est calculée avec ce secret serveur.
    // Si quelqu'un modifie le payload, la signature ne correspond plus.
    getJwtSecret(),
    {
      // HS256 = signature HMAC avec SHA-256 (clé secrète partagée).
      algorithm: 'HS256',
      // SÉCURITÉ : le jeton expire après 2 heures. Un jeton volé
      // devient inutilisable rapidement.
      expiresIn: '2h',
    }
  );
}

// ---------------------------------------------------------------------
// Vérification du jeton et récupération de l'utilisateur connecté
// ---------------------------------------------------------------------
// Utilisation dans une route :
//   const user = await requireUser(req, res);
//   if (!user) return;   // l'erreur 401 a déjà été envoyée
//
// SÉCURITÉ : c'est la SEULE source d'identité de l'API. On ne fait
// jamais confiance à un "sender_id" ou "user_id" envoyé dans le corps
// de la requête : l'identité vient toujours du jeton signé.
export async function requireUser(req, res) {
  // Le front envoie l'en-tête : Authorization: Bearer <jeton>
  const header = req.headers.authorization || '';
  const [type, token] = header.split(' ');

  if (type !== 'Bearer' || !token) {
    sendError(res, 401, 'Non connecté : jeton manquant.');
    return null;
  }

  let payload;
  try {
    // SÉCURITÉ : jwt.verify contrôle la signature ET la date d'expiration.
    // On impose l'algorithme HS256 : cela bloque l'attaque où un pirate
    // fabrique un jeton avec "alg: none" (sans signature).
    payload = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] });
  } catch {
    sendError(res, 401, 'Session invalide ou expirée : reconnectez-vous.');
    return null;
  }

  // On relit l'utilisateur en base : s'il a été supprimé depuis la
  // création du jeton, le jeton ne doit plus fonctionner.
  const sql = getSql();
  const rows = await sql`
    SELECT id, username, public_key
    FROM users
    WHERE id = ${payload.sub}
  `;

  if (rows.length === 0) {
    sendError(res, 401, 'Utilisateur introuvable : reconnectez-vous.');
    return null;
  }

  return rows[0];
}

// ---------------------------------------------------------------------
// Réponse d'erreur au format JSON : { "error": "message" }
// ---------------------------------------------------------------------
// Codes utilisés dans le projet :
//   400 = requête mal formée (champ manquant, valeur invalide)
//   401 = non authentifié (pas de jeton, jeton faux, mauvais mot de passe)
//   403 = authentifié mais action interdite
//   404 = ressource introuvable
//   405 = méthode HTTP non prévue
//   409 = conflit (ex : pseudo déjà pris)
//   500 = erreur interne du serveur
export function sendError(res, status, message) {
  res.status(status).json({ error: message });
}

// ---------------------------------------------------------------------
// Lecture du corps JSON de la requête
// ---------------------------------------------------------------------
// Vercel transforme automatiquement le JSON reçu en objet (req.body).
// Mais si le JSON est mal écrit, la lecture de req.body lève une erreur.
// Cette fonction renvoie toujours un objet ({} en cas de problème),
// ou null si le JSON est invalide (la route renverra alors une 400).
export function getBody(req) {
  try {
    const body = req.body;
    // Corps vide : on renvoie un objet vide.
    if (body === undefined || body === null || body === '') return {};
    // Certains clients envoient le JSON sans l'en-tête Content-Type :
    // Vercel le laisse alors sous forme de texte, on le convertit.
    if (typeof body === 'string') return JSON.parse(body);
    // Cas normal : déjà un objet.
    if (typeof body === 'object') return body;
    return null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------
// Refuse les méthodes HTTP non prévues pour une route
// ---------------------------------------------------------------------
// Exemple : allowMethods(req, res, ['POST']) dans login.js.
// Renvoie true si la méthode est acceptée, sinon envoie une erreur 405.
export function allowMethods(req, res, methods) {
  if (!methods.includes(req.method)) {
    res.setHeader('Allow', methods.join(', '));
    sendError(res, 405, `Méthode ${req.method} non autorisée ici.`);
    return false;
  }
  return true;
}
