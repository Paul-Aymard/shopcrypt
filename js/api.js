// =====================================================================
// js/api.js — Communication entre le navigateur et l'API (/api/...)
// =====================================================================
// Ce fichier est un "module" JavaScript : les pages l'importent avec
//   <script type="module"> import { login } from './js/api.js'; </script>
//
// Il gère :
//   - la session (jeton JWT + infos utilisateur) dans sessionStorage
//   - l'envoi des requêtes vers l'API avec le jeton
//   - une fonction par route de l'API (register, login, publishKey...)
//
// RAPPEL SÉCURITÉ : ce fichier ne contient AUCUN secret. Tout ce qui est
// dans /js est téléchargé par le navigateur et lisible par n'importe qui.
// =====================================================================

// Noms des cases utilisées dans sessionStorage.
const TOKEN_KEY = 'shopcrypt_token';
const USER_KEY = 'shopcrypt_user';

// ---------------------------------------------------------------------
// Gestion de la session
// ---------------------------------------------------------------------
// sessionStorage = petit espace de stockage du navigateur, propre à
// l'ONGLET. Il est vidé à la fermeture de l'onglet.
// SÉCURITÉ : on choisit sessionStorage plutôt que localStorage (qui,
// lui, reste même après fermeture du navigateur) pour limiter la durée
// de vie du jeton sur l'ordinateur. Limite à connaître : un script
// malveillant injecté dans la page (attaque XSS) pourrait le lire ; c'est
// pourquoi nos pages n'insèrent jamais de texte avec innerHTML.

export function saveSession(token, user) {
  sessionStorage.setItem(TOKEN_KEY, token);
  // sessionStorage ne stocke que du texte : on convertit l'objet en JSON.
  sessionStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function getUser() {
  const raw = sessionStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

// Met à jour une partie des infos utilisateur (ex : has_public_key = true
// après la publication de la clé publique).
export function updateUser(changes) {
  const user = getUser();
  if (user) sessionStorage.setItem(USER_KEY, JSON.stringify({ ...user, ...changes }));
}

export function logout() {
  // SÉCURITÉ : on vide TOUT le sessionStorage de l'onglet : le jeton,
  // les infos utilisateur ET la clé privée éventuellement chargée
  // (voir js/crypto.js). Le suivant sur l'ordinateur ne récupère rien.
  sessionStorage.clear();
  window.location.href = 'login.html';
}

// À appeler en haut des pages réservées aux utilisateurs connectés.
// Renvoie l'utilisateur, ou redirige vers login.html s'il n'y en a pas.
export function requireLogin() {
  const user = getUser();
  if (!getToken() || !user) {
    window.location.href = 'login.html';
    return null;
  }
  return user;
}

// ---------------------------------------------------------------------
// Fonction générique d'appel à l'API
// ---------------------------------------------------------------------
// Exemple : await apiFetch('/api/login', { method: 'POST', body: {...} })
// - ajoute l'en-tête Authorization si on est connecté
// - envoie et reçoit du JSON
// - lève une erreur avec le message de l'API si la réponse n'est pas OK
async function apiFetch(path, { method = 'GET', body } = {}) {
  const headers = {};

  // SÉCURITÉ : le jeton voyage dans l'en-tête "Authorization: Bearer ...".
  // C'est la seule preuve d'identité que le serveur accepte.
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    // fetch échoue seulement si le serveur est injoignable (réseau coupé,
    // "vercel dev" arrêté...).
    throw new Error('Serveur injoignable : vérifiez votre connexion.');
  }

  // On essaie de lire la réponse en JSON (elle peut être vide).
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    // 401 sur une route protégée = jeton expiré ou invalide : on vide la
    // session pour forcer une nouvelle connexion.
    if (response.status === 401 && token) {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(USER_KEY);
    }
    const message = (data && data.error) || `Erreur ${response.status}`;
    const error = new Error(message);
    error.status = response.status; // utile pour réagir selon le code
    throw error;
  }

  return data;
}

// ---------------------------------------------------------------------
// Une fonction par route de l'API
// ---------------------------------------------------------------------

// POST /api/register — crée le compte et ouvre la session.
export async function register(username, password) {
  const data = await apiFetch('/api/register', {
    method: 'POST',
    body: { username, password },
  });
  saveSession(data.token, data.user);
  return data.user;
}

// POST /api/login — vérifie les identifiants et ouvre la session.
export async function login(username, password) {
  const data = await apiFetch('/api/login', {
    method: 'POST',
    body: { username, password },
  });
  saveSession(data.token, data.user);
  return data.user;
}

// GET /api/keys — ma clé publique actuellement publiée (ou null). (étape 6)
export async function getMyPublicKey() {
  const data = await apiFetch('/api/keys');
  return data.public_key;
}

// PUT /api/keys — publie la clé PUBLIQUE (texte PEM). (étape 6)
// SÉCURITÉ : seule la clé publique passe par ici. Aucune fonction de ce
// fichier n'envoie la clé privée : elle ne quitte jamais le navigateur.
export async function publishKey(publicKeyPem) {
  const data = await apiFetch('/api/keys', {
    method: 'PUT',
    body: { public_key: publicKeyPem },
  });
  updateUser({ has_public_key: true });
  return data;
}

// GET /api/users — liste des destinataires possibles. (étape 7)
export async function getUsers() {
  const data = await apiFetch('/api/users');
  return data.users;
}

// POST /api/messages — envoie un message DÉJÀ CHIFFRÉ (base64). (étape 7)
export async function sendMessage(recipientId, ciphertext) {
  return apiFetch('/api/messages', {
    method: 'POST',
    body: { recipient_id: recipientId, ciphertext },
  });
}

// GET /api/messages — mes messages reçus (toujours chiffrés). (étape 8)
export async function getInbox() {
  const data = await apiFetch('/api/messages');
  return data.messages;
}

// ---------------------------------------------------------------------
// Barre de navigation : affiche le pseudo et le bouton de déconnexion
// ---------------------------------------------------------------------
// Chaque page contient <span id="nav-user"></span> dans son menu.
export function initNav() {
  const zone = document.getElementById('nav-user');
  if (!zone) return;

  const user = getUser();
  zone.textContent = ''; // on vide la zone

  if (user) {
    const name = document.createElement('span');
    // SÉCURITÉ : textContent (et jamais innerHTML) => un pseudo contenant
    // du code HTML/JavaScript s'affiche comme du simple texte (anti-XSS).
    name.textContent = `👤 ${user.username}`;

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn-link';
    button.textContent = 'Déconnexion';
    button.addEventListener('click', logout);

    zone.append(name, ' ', button);
  } else {
    const link = document.createElement('a');
    link.href = 'login.html';
    link.textContent = 'Connexion';
    zone.append(link);
  }
}
