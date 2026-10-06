# Plan du rapport (2 à 3 pages)

**Titre :** *ShopCrypt : messagerie chiffrée de bout en bout avec RSA-OAEP*
**Auteurs, formation, date.** Lien du site et du dépôt GitHub en en-tête.

---

## 1. Introduction (≈ ¼ page)
- Le contexte : une boutique en ligne où le vendeur transmet au client des informations sensibles (code de retrait, adresse).
- L'objectif : seul le destinataire peut lire le message. Ni le serveur ni un attaquant qui volerait la base ne le peuvent.
- Le choix demandé : RSA, utilisé directement, sans AES.

## 2. Rappels théoriques sur RSA (≈ ½ page)
- **Génération des clés :** p et q premiers, n = p·q, φ(n) = (p−1)(q−1), e premier avec φ(n), et d = e⁻¹ mod φ(n), calculé par Euclide étendu.
- **Chiffrement et déchiffrement :** c = mᵉ mod n et m = cᵈ mod n, calculés par exponentiation modulaire rapide.
- **Sécurité :** elle repose sur la difficulté de factoriser n. Illustration : avec n = 3233, la clé est cassée en moins d'une milliseconde dans demo-rsa.html.
- **Limite de RSA « brut » :** il est déterministe (la même lettre donne le même chiffré), ce qui le rend vulnérable à l'analyse de fréquence. D'où le besoin d'un **remplissage**.

## 3. Choix techniques (≈ ½ page)
- **RSA-OAEP, 2048 bits, SHA-256, e = 65537** : justifier chaque paramètre.
- **Limite de 190 octets :** k − 2·hLen − 2 = 256 − 64 − 2. On compte des octets UTF-8 (TextEncoder), pas des caractères.
- **Formats :** SPKI/PEM pour la clé publique, PKCS#8/PEM pour la clé privée, base64 pour le chiffré (344 caractères).
- **Web Crypto API :** pourquoi on ne code pas sa propre cryptographie en production.
- **Architecture :** front statique, Vercel Functions, Neon. Insérer un schéma du flux : Kofi publie sa clé, Awa chiffre, le serveur stocke, Kofi déchiffre.

## 4. Sécurité de l'application (≈ ½ page)
| Menace | Contre-mesure |
|---|---|
| Vol de la base de données | Les messages sont chiffrés, les mots de passe hachés avec bcrypt, aucune clé privée sur le serveur |
| Usurpation d'identité | JWT signé (HS256, 2 h). L'identité vient du jeton, jamais du corps de la requête |
| Injection SQL | Requêtes paramétrées |
| Énumération de comptes | Même message d'erreur, temps de réponse égalisé (haché leurre) |
| XSS | `textContent` uniquement, jamais d'`innerHTML` |
| Fuite de secrets | Variables d'environnement, `.gitignore` (`.env`, `*.pem`) |
| Données invalides | L'API vérifie la clé (RSA 2048, e = 65537) et le chiffré (344 caractères base64) |

## 5. Tests et démonstration (≈ ¼ page)
- Le scénario A chiffre, B déchiffre, C échoue, avec 2 ou 3 captures d'écran.
- Les tests réalisés :
  - 190 octets acceptés, 191 refusés (le navigateur lui-même lève une `OperationError`) ;
  - deux chiffrements du même texte donnent deux chiffrés différents ;
  - un chiffré produit par le navigateur a aussi été déchiffré par Node.js, ce qui montre la conformité au standard.

## 6. Limites et améliorations (≈ ¼ page)
- 190 octets maximum : pour des messages longs, il faudrait un **chiffrement hybride** (AES-GCM pour le message, RSA-OAEP pour la clé AES).
- Pas d'**authenticité** de l'expéditeur au sens cryptographique. On pourrait ajouter une **signature** RSA-PSS.
- Pas de vérification de l'authenticité des clés publiques : le serveur pourrait en substituer une (attaque de l'homme du milieu). Une solution serait de comparer les **empreintes** des clés en personne.
- Le jeton et la clé privée sont en sessionStorage, donc exposés en cas de XSS. Améliorations possibles : un cookie `HttpOnly` pour le jeton, une clé non exportable stockée dans IndexedDB.
- Perte du `.pem` : les messages deviennent illisibles pour toujours. C'est le prix du chiffrement de bout en bout.

## 7. Conclusion (quelques lignes)
Ce que le TP a permis de comprendre : la cryptographie asymétrique, le rôle du remplissage, la séparation entre ce qui est public et ce qui est secret, et la confiance minimale accordée au serveur.

---
**Annexes possibles :** le schéma SQL, des extraits de `js/crypto.js` (chiffrement et déchiffrement), une capture de demo-rsa.html.
