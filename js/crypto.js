// =====================================================================
// js/crypto.js — Toute la cryptographie RSA du projet (côté navigateur)
// =====================================================================
// On utilise la Web Crypto API : window.crypto.subtle.
// C'est une bibliothèque cryptographique INTÉGRÉE au navigateur, écrite et
// auditée par les éditeurs de navigateurs (Google, Mozilla, Apple...).
// On ne code pas RSA nous-mêmes ici : coder sa propre crypto pour un vrai
// usage est dangereux (le RSA "fait main" est seulement dans demo-rsa.html,
// à but pédagogique).
//
// RÈGLE D'OR DU PROJET : le chiffrement et le déchiffrement se font
// UNIQUEMENT ici, dans le navigateur. Le serveur ne voit jamais ni le
// message clair, ni la clé privée.
//
// Algorithme choisi : RSA-OAEP, clé de 2048 bits, hachage SHA-256,
// exposant public e = 65537.
// =====================================================================

// ---------------------------------------------------------------------
// Paramètres RSA-OAEP
// ---------------------------------------------------------------------
const RSA_PARAMS = {
  // RSA-OAEP = RSA avec le "remplissage" OAEP (Optimal Asymmetric
  // Encryption Padding). OAEP ajoute de l'aléatoire au message avant le
  // calcul RSA : chiffrer deux fois le même texte donne deux chiffrés
  // différents, et un attaquant ne peut pas tester des messages devinés.
  name: 'RSA-OAEP',

  // Taille du module n = p × q : 2048 bits (= 256 octets).
  // C'est le minimum recommandé aujourd'hui (ANSSI, NIST).
  modulusLength: 2048,

  // Exposant public e = 65537, écrit en octets : 0x01 0x00 0x01.
  // 65537 = 2^16 + 1 : il est premier, et son écriture binaire
  // (10000000000000001) ne contient que deux "1", ce qui rend le
  // chiffrement (m^e mod n) rapide.
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),

  // Fonction de hachage utilisée À L'INTÉRIEUR d'OAEP : SHA-256.
  // Elle produit 32 octets ; ce chiffre sert au calcul des 190 octets.
  hash: 'SHA-256',
};

// ---------------------------------------------------------------------
// Limite de taille : 190 octets par message
// ---------------------------------------------------------------------
// D'où vient 190 ?
//   - La clé fait 2048 bits = 256 octets : RSA ne peut chiffrer qu'un bloc
//     plus petit que n, donc au plus 256 octets.
//   - OAEP a besoin de place pour sa "sécurité" : 2 empreintes SHA-256
//     (2 × 32 octets = 64) + 2 octets de structure = 66 octets.
//   - Il reste donc : 256 − 66 = 190 octets pour le message.
// Formule générale : k − 2·hLen − 2  (k = taille de la clé en octets,
// hLen = taille du hachage en octets).
export const MAX_MESSAGE_BYTES = 256 - 2 * 32 - 2; // = 190

// Compte les OCTETS (et non les caractères) d'un texte en UTF-8.
// Exemple : "a" = 1 octet, "é" = 2 octets, "€" = 3 octets, "😀" = 4 octets.
// C'est pourquoi le compteur de write.html utilise TextEncoder.
export function byteLength(text) {
  return new TextEncoder().encode(text).length;
}

// ---------------------------------------------------------------------
// Outils de conversion : octets <-> base64 <-> PEM
// ---------------------------------------------------------------------
// base64 = façon d'écrire des octets avec 64 caractères lisibles
// (A-Z a-z 0-9 + /). 3 octets deviennent 4 caractères.
// Utile car on ne peut pas mettre des octets "bruts" dans du JSON ou
// dans une base de données texte.

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary); // btoa = "binary to ASCII" (encode en base64)
}

function base64ToBytes(base64) {
  const binary = atob(base64); // atob = "ASCII to binary" (décode le base64)
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// PEM = le base64 d'une clé, coupé en lignes de 64 caractères et entouré
// d'un en-tête et d'un pied, par exemple :
//   -----BEGIN PUBLIC KEY-----
//   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
//   -----END PUBLIC KEY-----
function toPem(buffer, label) {
  const base64 = bytesToBase64(buffer);
  const lines = base64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function fromPem(pem, label) {
  const header = `-----BEGIN ${label}-----`;
  const footer = `-----END ${label}-----`;
  const text = String(pem).trim();
  if (!text.startsWith(header) || !text.endsWith(footer)) {
    throw new Error(`Fichier invalide : ce n'est pas une "${label}" au format PEM.`);
  }
  // On enlève l'en-tête, le pied et tous les retours à la ligne.
  const base64 = text.slice(header.length, text.length - footer.length).replace(/\s+/g, '');
  return base64ToBytes(base64);
}

// ---------------------------------------------------------------------
// 1) Génération de la paire de clés
// ---------------------------------------------------------------------
// Renvoie { publicKey, privateKey } (objets CryptoKey).
// Le navigateur tire au hasard deux grands nombres premiers p et q
// (1024 bits chacun), calcule n = p × q, puis d = e⁻¹ mod φ(n).
// extractable = true : on autorise l'export (nécessaire pour publier la
// clé publique et télécharger la clé privée).
export async function generateKeyPair() {
  return crypto.subtle.generateKey(RSA_PARAMS, true, ['encrypt', 'decrypt']);
}

// ---------------------------------------------------------------------
// 2) Export des clés en PEM
// ---------------------------------------------------------------------
// SPKI (SubjectPublicKeyInfo) = format standard d'une clé PUBLIQUE.
// Il contient n, e et l'identifiant de l'algorithme (RSA).
export async function exportPublicKeyPem(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return toPem(spki, 'PUBLIC KEY');
}

// PKCS#8 = format standard d'une clé PRIVÉE. Il contient n, e, d, p, q
// et quelques valeurs pré-calculées pour accélérer le déchiffrement.
// SÉCURITÉ : ce texte est SECRET. Il est seulement proposé au
// téléchargement (cle-privee.pem) ; il n'est JAMAIS envoyé à l'API.
export async function exportPrivateKeyPem(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  return toPem(pkcs8, 'PRIVATE KEY');
}

// ---------------------------------------------------------------------
// 3) Import des clés depuis un PEM
// ---------------------------------------------------------------------
// Clé publique d'un destinataire (reçue de l'API) -> utilisable pour chiffrer.
export async function importPublicKeyPem(pem) {
  return crypto.subtle.importKey(
    'spki',
    fromPem(pem, 'PUBLIC KEY'),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,       // non exportable : on n'en a pas besoin
    ['encrypt']  // usage autorisé : chiffrer uniquement
  );
}

// Clé privée (fichier .pem de l'utilisateur) -> utilisable pour déchiffrer.
export async function importPrivateKeyPem(pem) {
  try {
    return await crypto.subtle.importKey(
      'pkcs8',
      fromPem(pem, 'PRIVATE KEY'),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      // SÉCURITÉ : non exportable. Une fois importée, même un script de
      // la page ne peut plus en relire le contenu via la Web Crypto API.
      false,
      ['decrypt'] // usage autorisé : déchiffrer uniquement
    );
  } catch (err) {
    if (err.message.startsWith('Fichier invalide')) throw err;
    throw new Error('Fichier .pem illisible : ce n’est pas une clé privée RSA valide.');
  }
}

// ---------------------------------------------------------------------
// 4) Vérifier qu'une clé privée correspond à une clé publique
// ---------------------------------------------------------------------
// Deux clés RSA forment une paire si elles ont le MÊME module n.
// On exporte les deux au format JWK (JSON Web Key), qui donne n en clair
// (champ "n", en base64url), et on compare.
// Utile pour prévenir l'utilisateur s'il recharge une ancienne clé.
export async function privateKeyMatchesPublic(privatePem, publicPem) {
  const algo = { name: 'RSA-OAEP', hash: 'SHA-256' };
  // Import temporaire en "exportable" uniquement pour lire n.
  const priv = await crypto.subtle.importKey('pkcs8', fromPem(privatePem, 'PRIVATE KEY'), algo, true, ['decrypt']);
  const pub = await crypto.subtle.importKey('spki', fromPem(publicPem, 'PUBLIC KEY'), algo, true, ['encrypt']);
  const privJwk = await crypto.subtle.exportKey('jwk', priv);
  const pubJwk = await crypto.subtle.exportKey('jwk', pub);
  return privJwk.n === pubJwk.n && privJwk.e === pubJwk.e;
}

// ---------------------------------------------------------------------
// 5) Chiffrement d'un message (utilisé par write.html)
// ---------------------------------------------------------------------
// texte clair --TextEncoder--> octets --RSA-OAEP(clé publique)--> 256 octets
// --base64--> 344 caractères (stockés en base et affichés).
export async function encryptMessage(publicKey, text) {
  // TextEncoder transforme le texte en octets UTF-8.
  const data = new TextEncoder().encode(text);

  if (data.length === 0) {
    throw new Error('Le message est vide.');
  }
  if (data.length > MAX_MESSAGE_BYTES) {
    throw new Error(`Message trop long : ${data.length} octets (maximum ${MAX_MESSAGE_BYTES}).`);
  }

  // CRYPTO : le chiffrement RSA-OAEP proprement dit.
  // Le navigateur ajoute le remplissage OAEP (avec une "graine" aléatoire),
  // puis calcule c = m^e mod n avec la clé publique du destinataire.
  const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);

  // Le résultat fait toujours 256 octets (la taille de n), quel que soit
  // le message : un observateur ne peut même pas deviner sa longueur exacte.
  return bytesToBase64(encrypted);
}

// ---------------------------------------------------------------------
// 6) Déchiffrement d'un message (utilisé par inbox.html)
// ---------------------------------------------------------------------
// base64 --> 256 octets --RSA-OAEP(clé privée)--> octets --TextDecoder--> texte
export async function decryptMessage(privateKey, ciphertextBase64) {
  let bytes;
  try {
    bytes = base64ToBytes(ciphertextBase64);
  } catch {
    throw new Error('Chiffré illisible : ce n’est pas du base64 valide.');
  }

  try {
    // CRYPTO : calcule m = c^d mod n avec la clé privée, puis vérifie et
    // retire le remplissage OAEP. Si la clé n'est pas la bonne, la
    // vérification OAEP échoue et le navigateur lève une "OperationError".
    const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, bytes);
    return new TextDecoder().decode(decrypted);
  } catch {
    // On ne révèle pas plus de détails : on indique juste que ça ne correspond pas.
    throw new Error('Déchiffrement impossible : cette clé privée ne correspond pas à ce message.');
  }
}

// ---------------------------------------------------------------------
// 7) Garder la clé privée pendant la session
// ---------------------------------------------------------------------
// Le site a plusieurs pages : quand on change de page, la mémoire
// JavaScript est effacée. Pour ne pas redemander le fichier .pem à chaque
// page, on garde son texte dans sessionStorage (propre à l'onglet,
// vidé à la fermeture de l'onglet et à la déconnexion).
// SÉCURITÉ : la clé reste UNIQUEMENT dans ce navigateur ; aucune fonction
// ne l'envoie au serveur. Limite à citer : un script malveillant injecté
// dans la page (XSS) pourrait la lire ; d'où notre règle "jamais
// d'innerHTML" et la possibilité de "Oublier la clé" à tout moment.
const PRIVATE_KEY_STORAGE = 'shopcrypt_private_key';

// Clé déjà importée pour la page en cours (évite de ré-importer).
let cachedPrivateKey = null;

// Importe la clé (vérifie qu'elle est valide), puis la mémorise.
export async function rememberPrivateKey(pem) {
  const key = await importPrivateKeyPem(pem); // lève une erreur si invalide
  sessionStorage.setItem(PRIVATE_KEY_STORAGE, pem.trim());
  cachedPrivateKey = key;
  return key;
}

// Renvoie la clé privée chargée, ou null s'il faut demander le .pem.
export async function getRememberedPrivateKey() {
  if (cachedPrivateKey) return cachedPrivateKey;
  const pem = sessionStorage.getItem(PRIVATE_KEY_STORAGE);
  if (!pem) return null;
  try {
    cachedPrivateKey = await importPrivateKeyPem(pem);
    return cachedPrivateKey;
  } catch {
    forgetPrivateKey();
    return null;
  }
}

// Texte PEM mémorisé (pour vérifier la correspondance avec la clé publique).
export function getRememberedPrivatePem() {
  return sessionStorage.getItem(PRIVATE_KEY_STORAGE);
}

export function forgetPrivateKey() {
  sessionStorage.removeItem(PRIVATE_KEY_STORAGE);
  cachedPrivateKey = null;
}

// ---------------------------------------------------------------------
// 8) Téléchargement d'un fichier texte (cle-privee.pem)
// ---------------------------------------------------------------------
// Le fichier est fabriqué DANS le navigateur (Blob) et enregistré sur
// l'ordinateur : aucune requête réseau, rien ne passe par le serveur.
export function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
