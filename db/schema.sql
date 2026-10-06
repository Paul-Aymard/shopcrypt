-- =====================================================================
-- ShopCrypt — Schéma de la base de données (PostgreSQL / Neon)
-- =====================================================================
-- Ce fichier crée les 2 tables du projet :
--   1) users    : les comptes (vendeurs et clients)
--   2) messages : les messages CHIFFRÉS envoyés d'un utilisateur à un autre
--
-- À exécuter UNE fois dans l'éditeur SQL de Neon (onglet "SQL Editor").
-- Le script peut être relancé sans erreur grâce aux "IF NOT EXISTS".
-- =====================================================================


-- ---------------------------------------------------------------------
-- Extension pgcrypto : fournit la fonction gen_random_uuid().
-- Sur PostgreSQL 13 et plus, gen_random_uuid() existe déjà nativement ;
-- cette ligne est donc une simple précaution (elle ne fait rien si
-- la fonction est déjà disponible).
-- ---------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- =====================================================================
-- Table 1 : users
-- =====================================================================
CREATE TABLE IF NOT EXISTS users (
    -- Identifiant unique au format UUID (ex : 3f2b8c1e-...).
    -- SÉCURITÉ : un UUID aléatoire ne se devine pas, contrairement à
    -- un compteur 1, 2, 3... qu'un attaquant pourrait énumérer.
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Pseudo de connexion. UNIQUE = deux comptes ne peuvent pas avoir
    -- le même pseudo (PostgreSQL refusera l'insertion du doublon).
    username      VARCHAR(50)  NOT NULL UNIQUE,

    -- SÉCURITÉ : on ne stocke JAMAIS le mot de passe en clair.
    -- On stocke son "haché" bcrypt (une empreinte à sens unique,
    -- ex : $2a$10$N9qo8uLOickgx2ZMRZoMy...). Si la base fuite,
    -- l'attaquant ne lit pas les mots de passe.
    password_hash TEXT         NOT NULL,

    -- CRYPTO : clé PUBLIQUE RSA de l'utilisateur, au format PEM
    -- (texte commençant par -----BEGIN PUBLIC KEY-----).
    -- NULLABLE : vaut NULL tant que l'utilisateur n'a pas encore
    -- généré sa paire de clés sur la page keys.html.
    -- La clé PRIVÉE n'a AUCUNE colonne ici : elle ne quitte jamais
    -- le navigateur de son propriétaire. Le serveur ne peut donc
    -- techniquement pas déchiffrer les messages.
    public_key    TEXT         NULL,

    -- Date de création du compte (remplie automatiquement).
    -- TIMESTAMPTZ = date + heure + fuseau horaire.
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);


-- =====================================================================
-- Table 2 : messages
-- =====================================================================
CREATE TABLE IF NOT EXISTS messages (
    -- Identifiant unique du message (UUID aléatoire, comme pour users).
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Expéditeur : doit être un id existant dans users (clé étrangère).
    -- ON DELETE CASCADE : si le compte est supprimé, ses messages
    -- envoyés sont supprimés aussi (pas de message "orphelin").
    sender_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Destinataire : même principe que sender_id.
    recipient_id  UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- CRYPTO : le message CHIFFRÉ en RSA-OAEP, encodé en base64.
    -- Avec une clé de 2048 bits, le chiffré fait toujours 256 octets,
    -- soit 344 caractères en base64. Le serveur ne voit QUE ceci :
    -- il ne connaît jamais le texte clair.
    ciphertext    TEXT         NOT NULL,

    -- Date d'envoi (remplie automatiquement).
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Règle de cohérence : on interdit de s'envoyer un message à soi-même.
    CONSTRAINT chk_pas_a_soi_meme CHECK (sender_id <> recipient_id)
);


-- =====================================================================
-- Index : accélère la requête la plus fréquente de l'application,
-- "donne-moi MES messages reçus, du plus récent au plus ancien"
-- (utilisée par GET /api/messages pour la page inbox.html).
-- Un index fonctionne comme le sommaire d'un livre : PostgreSQL
-- trouve directement les lignes au lieu de lire toute la table.
-- =====================================================================
CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages (recipient_id, created_at DESC);
