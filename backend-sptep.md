# Spec Backend — Projet IDS/IPS Intelligent (NestJS + MySQL)

## Contexte du projet

Stage cybersécurité (2 mois). Architecture retenue par le maître de stage : 2 VMs, sans firewall, focus sur supervision IDS/IPS.

- **VM1** : Suricata (IDS) + Wazuh (SIEM, manager+indexer+dashboard) + ce backend (NestJS + MySQL) — déjà installés et fonctionnels
- **VM2** : Frontend React (à venir, pas dans ce scope)

Ce backend sert d'intermédiaire entre Wazuh (source des alertes de sécurité) et un frontend React custom, avec authentification, gestion des droits, et génération de rapports — fonctionnalités que le dashboard Wazuh natif ne couvre pas nativement de la façon demandée.

## Stack imposée

- **Framework** : NestJS (TypeScript)
- **Base de données** : MySQL via TypeORM
- **Auth** : JWT + MFA (TOTP, type Google Authenticator)
- **Temps réel** : WebSocket (Socket.io via `@nestjs/websockets`)
- **Rapports** : génération PDF et Excel
- **Source des données de sécurité** : API REST Wazuh (port 55000, déjà installé sur la même VM)

## Ce que MySQL doit stocker (uniquement — pas de données temps réel dedans)

- Utilisateurs (username, password hashé, rôle, statut MFA, secret MFA)
- Rôles et permissions (RBAC)
- Historique des rapports générés (métadonnées : qui, quand, quel format, filtre appliqué)
- Logs d'audit des actions utilisateurs (qui a fait quoi, quand — ex: login, changement de rôle, génération de rapport, consultation d'alerte)

**Important : MySQL ne doit JAMAIS être utilisé pour stocker ou requêter des alertes de sécurité en temps réel.** Les alertes vivent dans Wazuh Indexer (OpenSearch) — le backend les récupère via l'API Wazuh à la demande ou par polling, ne les duplique pas en base sauf si explicitement nécessaire pour l'historique (dans ce cas, stocker seulement un résumé/référence, pas le payload complet).

## Modules à générer

### 1. Module `auth`
- Login (`POST /auth/login`) : vérifie username/password (bcrypt), retourne soit un JWT direct (si MFA désactivé pour ce user), soit un statut "MFA requis" avec un token temporaire
- Vérification MFA (`POST /auth/mfa/verify`) : prend le token temporaire + le code TOTP à 6 chiffres, retourne le JWT final si valide
- Setup MFA (`POST /auth/mfa/setup`) : génère un secret TOTP (librairie `otplib`), retourne un QR code (librairie `qrcode`) à scanner dans Google Authenticator
- Guard JWT (`@nestjs/passport` + `passport-jwt`) pour protéger les routes
- Refresh token (optionnel si le temps permet)

### 2. Module `users`
- Entité `User` : id, username, passwordHash, role (enum: admin/analyst/viewer), mfaEnabled, mfaSecret, createdAt
- CRUD complet (create/read/update/delete), réservé aux admins
- Endpoint `GET /users/me` pour le profil de l'utilisateur connecté

### 3. Module `roles` (RBAC)
- Rôles fixes pour commencer : `admin` (tout), `analyst` (lecture alertes + génération rapports), `viewer` (lecture seule dashboard)
- Guard `RolesGuard` + decorator `@Roles('admin')` pour protéger les endpoints sensibles (gestion users, config)

### 4. Module `wazuh` (intégration API Wazuh)
- Service qui s'authentifie auprès de l'API Wazuh (`GET https://<IP_VM1>:55000/security/user/authenticate`, Basic Auth avec le compte `wazuh-wui`, certificat auto-signé donc `rejectUnauthorized: false`) et cache le token JWT Wazuh (expire après un moment, prévoir un refresh automatique)
- Endpoint `GET /alerts` : proxy vers l'API Wazuh pour récupérer les alertes récentes (filtrable par sévérité, date, IP source/dest)
- Endpoint `GET /alerts/stats` : agrégats pour les graphiques du dashboard (nombre d'attaques par type, par IP, évolution dans le temps)
- Endpoint `GET /agents/status` : statut des agents Wazuh connectés

### 5. Module `realtime` (WebSocket)
- Gateway Socket.io (`@WebSocketGateway`)
- Un job planifié (`setInterval` ou `@nestjs/schedule` avec un cron court, ex: toutes les 5 secondes) interroge l'API Wazuh pour les nouvelles alertes depuis le dernier check, et les broadcast à tous les clients connectés via `server.emit('new-alert', alertData)`
- Prévoir une room/namespace si on veut différencier par rôle plus tard (pas obligatoire au début)

### 6. Module `reports`
- Endpoint `POST /reports/generate` : prend un filtre (période, type d'alerte...), génère un PDF (librairie `pdfkit` ou `puppeteer`) ou un Excel (librairie `exceljs`) résumant les alertes de la période
- Enregistre une entrée dans la table `reports` (MySQL) avec métadonnées (qui, quand, format, filtre)
- Retourne le fichier en téléchargement

### 7. Module `audit`
- Entité `AuditLog` : id, userId, action (string), targetEntity (string, optionnel), timestamp, ipAddress
- Un interceptor global ou un service appelé manuellement dans les endpoints sensibles (login, changement de rôle, génération de rapport, suppression) qui insère une ligne dans `AuditLog`
- Endpoint `GET /audit-logs` (admin uniquement) avec filtres (utilisateur, date, action) pour la traçabilité demandée dans le cahier des charges

## Variables d'environnement attendues (.env)

```
# MySQL
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=ids_app
DB_PASSWORD=
DB_DATABASE=ids_ips_db

# JWT
JWT_SECRET=
JWT_EXPIRATION=1h

# Wazuh API
WAZUH_API_URL=https://192.168.101.128:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=

# App
PORT=3000
```

## Contraintes techniques importantes

- Le serveur NestJS doit écouter sur `0.0.0.0:3000` (pas `localhost`) pour être joignable depuis le frontend React sur VM2 (`192.168.101.130`)
- CORS à activer pour autoriser les requêtes depuis l'IP/domaine du frontend
- Toutes les requêtes vers l'API Wazuh doivent gérer le certificat auto-signé (`rejectUnauthorized: false` dans l'agent HTTPS axios/node)
- `synchronize: true` sur TypeORM uniquement en dev — le mentionner en commentaire dans le code
- Les mots de passe utilisateurs doivent être hashés avec `bcrypt`, jamais stockés en clair
- Les secrets MFA doivent être stockés chiffrés si possible (ou au minimum jamais exposés dans les réponses API après le setup initial)

## Livrables attendus du code généré

- Structure de projet NestJS standard avec modules séparés comme listé ci-dessus
- Fichier `.env.example` (sans les vraies valeurs)
- Un `README.md` avec les instructions de lancement
- Entités TypeORM correctement définies avec relations si besoin (ex: User → AuditLog)
- Endpoints testables via un fichier `.http` ou une collection Postman/Thunder Client si possible

## Ce qui n'est PAS dans ce scope (pour plus tard / autre prompt)
- Le frontend React
- Le déploiement en production (PM2, Nginx) — c'est du dev local sur VM1 pour l'instant
- Snort (on utilise Suricata uniquement)
