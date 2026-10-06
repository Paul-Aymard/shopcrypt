# ShopCrypt — Messagerie chiffrée RSA-OAEP

TP de cryptographie (Master 1). Une mini-boutique où un **vendeur** envoie un message
confidentiel à son **client**. Le message est chiffré avec **RSA-OAEP 2048 bits** directement
dans le navigateur (Web Crypto API) : le serveur ne stocke et ne voit que du texte chiffré.

- **Site en ligne :** https://shopcrypt-w3fq.vercel.app
- **Code :** https://github.com/Paul-Aymard/shopcrypt
- **Guide de 2 pages :** [docs/Guide-TP-ShopCrypt.pdf](docs/Guide-TP-ShopCrypt.pdf)
- **Scénario de démonstration :** [docs/SCENARIO-DEMO.md](docs/SCENARIO-DEMO.md)
- **Plan du rapport :** [docs/PLAN-RAPPORT.md](docs/PLAN-RAPPORT.md)

## Stack

| Partie | Technologie |
|---|---|
| Front | HTML, CSS, JavaScript pur (modules ES, sans framework ni bundler) |
| Cryptographie | Web Crypto API (`window.crypto.subtle`), uniquement dans le navigateur |
| API | Vercel Functions (Node.js), dossier `/api` |
| Base de données | Neon (PostgreSQL), créée depuis l'onglet Storage de Vercel |
| Paquets npm | `@neondatabase/serverless`, `bcryptjs`, `jsonwebtoken` |

## Choix cryptographiques

- **RSA-OAEP**, module de **2048 bits**, hachage **SHA-256**, exposant public **65537**. Pas d'AES.
- **190 octets maximum** par message, car 256 − 2×32 − 2 = 190 (taille de la clé − 2 empreintes SHA-256 − 2).
- Le chiffré fait toujours 256 octets, soit **344 caractères en base64**.
- La **clé publique** est au format SPKI/PEM et enregistrée dans Neon.
- La **clé privée** est au format PKCS#8/PEM, téléchargée (`cle-privee.pem`) et réimportable. **Elle n'est jamais envoyée à l'API.**

## Arborescence

```
db/schema.sql        Tables users et messages
api/_lib.js          Connexion Neon, signature et vérification du JWT, erreurs
api/register.js      POST  inscription (bcrypt) -> JWT
api/login.js         POST  connexion -> JWT
api/keys.js          GET/PUT  ma clé publique
api/users.js         GET   destinataires ayant une clé publique
api/messages.js      POST  envoyer un chiffré / GET  mes messages reçus
js/api.js            Appels à l'API et session (sessionStorage)
js/crypto.js         Génération, export, import, chiffrement, déchiffrement RSA-OAEP
css/style.css        Style (thème clair et sombre, adapté au mobile)
index.html           Catalogue de 6 produits (FCFA)
login.html           Inscription et connexion
keys.html            Générer, télécharger, publier et réimporter les clés
write.html           Compteur d'octets, Chiffrer, Envoyer
inbox.html           Messages reçus, Déchiffrer
demo-rsa.html        RSA codé à la main en BigInt, avec toutes les étapes
```

## Installation

### 1. Prérequis
- Node.js 20 ou plus récent, et un compte GitHub et Vercel.
- La CLI Vercel :
  ```bash
  npm i -g vercel
  ```

### 2. Projet Vercel et base Neon
1. Sur Vercel : **Add New → Project**, puis importez le dépôt GitHub `shopcrypt`.
2. Dans le projet : **Storage → Create Database → Neon**, puis connectez la base au projet. La variable `DATABASE_URL` est ajoutée automatiquement.
3. Dans la console Neon (**Open in Neon → SQL Editor**), collez et exécutez [db/schema.sql](db/schema.sql).

### 3. Secret JWT
Générez une valeur aléatoire :
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```
Dans Vercel, ouvrez **Settings → Environment Variables** et ajoutez `JWT_SECRET` avec cette valeur, au moins pour Production.

### 4. Lancer en local
```bash
npm install
```
```bash
vercel link
```
Créez ensuite un fichier **`.env`** à la racine, sur le modèle de [.env.example](.env.example). Il doit contenir :
- `DATABASE_URL` : à copier depuis Neon → Connect ;
- `JWT_SECRET` : générez-en un comme à l'étape 3.

Puis lancez le serveur :
```bash
vercel dev
```
Ouvrez enfin http://localhost:3000.

> **Pièges connus**
> - `vercel dev` lit **`.env`**, pas `.env.local`. De plus, les variables Neon de type « Secret » ne sont pas téléchargées par `vercel env pull`.
> - **Ne mettez pas** de script `"dev": "vercel dev"` dans `package.json` : `vercel dev` s'appellerait lui-même en boucle.
> - Pour tester l'API avec PowerShell 5.1, lancez d'abord :
>   ```powershell
>   [System.Net.ServicePointManager]::Expect100Continue = $false
>   ```
> - `.env`, `.env.local` et `*.pem` ne doivent **jamais** être commités. Le `.gitignore` les bloque.

### 5. Déploiement
Chaque `git push` sur `main` redéploie automatiquement le site en production. Vous pouvez aussi déployer à la main :
```bash
vercel --prod
```

## Sécurité, en résumé
- Les mots de passe sont hachés avec **bcrypt** (coût 10, sel aléatoire). Un pseudo inconnu et un mauvais mot de passe donnent le même message d'erreur.
- Le **JWT** est signé en HS256 et expire au bout de 2 h. L'identité vient **toujours du jeton**, jamais du corps de la requête.
- Toutes les requêtes SQL sont **paramétrées**.
- L'API refuse tout ce qui n'est pas une clé publique RSA 2048 bits avec e = 65537. Elle refuse aussi tout « chiffré » qui ne fait pas 344 caractères base64.
- Les pages affichent tout le texte avec **`textContent`** et jamais avec `innerHTML`, ce qui protège contre le XSS.
