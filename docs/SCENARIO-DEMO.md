# Scénario de démonstration (environ 10 minutes)

**Personnages :**
- **Awa** : la vendeuse, qui envoie le message (A).
- **Kofi** : le client, qui reçoit le message (B).
- **Chris** : un intrus qui essaie de lire un message qui ne lui est pas destiné (C).

**Matériel :** deux navigateurs, ou une fenêtre normale et une fenêtre privée, puisque chaque onglet a sa propre session. Ouvrez aussi la console Neon dans un troisième onglet.

---

## 0. Introduction (1 min)
Ouvrez https://shopcrypt-w3fq.vercel.app et présentez le catalogue.

> « Sur ShopCrypt, le vendeur envoie au client des informations confidentielles. Elles sont chiffrées en RSA **dans le navigateur** : même notre serveur ne peut pas les lire. »

## 1. Kofi crée ses clés (2 min)
1. Kofi s'inscrit sur **login.html** et arrive sur **keys.html**.
2. Il clique sur **Générer ma paire de clés**. La clé publique s'affiche au format PEM.
   > « Le navigateur vient de tirer p et q, de 1024 bits chacun, et de calculer n, φ(n) et d. »
3. Il clique sur **Télécharger cle-privee.pem**, puis sur **Publier ma clé publique**.
4. Ouvrez l'onglet Réseau (F12) : seule la clé **publique** est partie dans le `PUT /api/keys`.

## 2. Awa chiffre et envoie (2 min)
1. Awa s'inscrit et ouvre **write.html**. Elle choisit **kofi** comme destinataire.
2. Elle tape : *« Votre commande n°42 est prête. Code de retrait : 7781 »*. Montrez le compteur, par exemple **58 / 190 octets**.
3. Ajoutez des « é » pour dépasser 190 : le bouton **Chiffrer** se désactive. Expliquez d'où vient 190 : 256 − 2×32 − 2.
4. Revenez à un texte normal et cliquez sur **Chiffrer** : 344 caractères base64 s'affichent.
5. Cliquez une deuxième fois sur **Chiffrer** : le chiffré est **différent**.
   > « C'est l'effet d'OAEP : il ajoute de l'aléatoire avant le calcul RSA. »
6. Cliquez sur **Envoyer** : la confirmation ✅ s'affiche.

## 3. Le serveur ne peut pas lire (1 min)
Dans la console Neon, lancez :
```sql
SELECT ciphertext FROM messages;
```
> « Voilà tout ce que le serveur possède : du base64 illisible. Et il n'a aucune clé privée. »

## 4. Kofi déchiffre (1 min)
1. Kofi ouvre **inbox.html** : une carte affiche « De : awa », la date et le chiffré.
2. Il clique sur **Déchiffrer**. Si sa clé n'est pas chargée, la page lui demande `cle-privee.pem`.
3. Le message clair s'affiche ✅.

## 5. Chris échoue (1 min)
1. Chris s'inscrit, génère ses propres clés et télécharge **son** `cle-privee.pem`.
2. Dans l'onglet de Kofi, chargez le `.pem` de **Chris** et cliquez sur **Déchiffrer**.
3. ❌ *« Déchiffrement impossible : cette clé privée ne correspond pas à ce message. »*
   > « Le message a été fermé avec le cadenas de Kofi : seule la clé de Kofi l'ouvre. »
4. Vous pouvez aussi montrer que Chris, connecté avec son propre compte, a une boîte de réception **vide** : l'API ne lui renvoie que ses messages à lui.

## 6. RSA à la main (2 min)
Ouvrez **demo-rsa.html** :
1. Avec p = 61, q = 53 et e = 17, on obtient n = 3233, φ(n) = 3120 et d = 2753 (montrez le tableau d'Euclide étendu).
2. Chiffrez m = 65, ce qui donne c = 2790. Montrez le tableau « carré et multiplication », puis le déchiffrement qui redonne 65.
3. Chiffrez le mot « SHOPCRYPT » : les deux « P » donnent le **même** chiffré. RSA sans remplissage est donc déterministe, et c'est pour ça que le site utilise OAEP.
4. Cliquez sur **Factoriser n** : la clé est cassée en moins d'une milliseconde.
   > « D'où la nécessité de 2048 bits. »

---

## Si quelque chose ne marche pas le jour J
| Problème | Solution |
|---|---|
| « Session invalide ou expirée » | Le jeton a plus de 2 h : reconnectez-vous |
| Kofi n'apparaît pas dans la liste des destinataires | Il n'a pas publié sa clé publique (keys.html) |
| « Chargez d'abord votre fichier » | Rechargez `cle-privee.pem` sur inbox.html ou keys.html |
| Kofi a régénéré ses clés | Les anciens messages ne se déchiffrent qu'avec l'**ancien** .pem |
