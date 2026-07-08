# IDS/IPS Intelligent Cybersecurity Dashboard Backend (NestJS + MySQL)

Ce projet est le backend d'un tableau de bord de cybersécurité pour la supervision d'un système IDS/IPS. Il sert d'intermédiaire entre l'instance Wazuh (qui regroupe les logs Wazuh et Suricata sur la VM1) et le frontend React (sur la VM2).

Il implémente l'authentification sécurisée, la gestion fine des droits (RBAC), le double facteur (MFA), la génération automatique de rapports de sécurité (PDF/Excel), le stockage des logs d'audit utilisateur, et la diffusion d'alertes en temps réel via WebSocket.

---

## Fonctionnalités Implémentées

1. **Authentification & Double Facteur (TOTP)**
   - Hashage des mots de passe avec `bcrypt`.
   - Setup MFA (`POST /auth/mfa/setup`) générant une clé secrète et un QR Code base64 à scanner via Google Authenticator.
   - Guard de route JWT et interception des jetons temporaires tant que le MFA n'est pas validé.
2. **Gestion des Rôles (RBAC)**
   - Rôles fixes : `admin` (supervision totale + CRUD utilisateurs), `analyst` (consulter les alertes + générer des rapports), `viewer` (lecture seule des statistiques).
3. **Audit Interceptor**
   - Intercepteur automatique insérant des logs dans MySQL pour la traçabilité des actions sensibles (Login, suppression d'utilisateur, changement de rôle, génération de rapport).
4. **Intégration Wazuh**
   - Authentification à l'API Wazuh (Basic Auth sur port 55000) et cache du JWT Wazuh.
   - Proxying des alertes récentes filtrables par sévérité, IP et dates.
   - Statistiques agrégées pour les graphes (Top IPs, types d'attaques, distribution de sévérité, série temporelle).
   - Statut des agents connectés.
   - **Simulation Fallback** : Si le service Wazuh ou l'indexer n'est pas accessible, un générateur simule des alertes Suricata/Wazuh réalistes afin de garantir le bon fonctionnement en environnement de développement local.
5. **Diffusion Temps Réel (WebSockets)**
   - Socket.io Gateway diffusant un événement `new-alert` toutes les 5 secondes aux clients connectés.
6. **Rapports de Sécurité**
   - Génération de PDF esthétiques (via `pdfkit`) avec entête personnalisé et tableau des alertes.
   - Génération de classeurs Excel (via `exceljs`) avec styles et filtres appliqués.
   - Historique complet de la création des rapports enregistrés en BDD.

---

## Variables d'Environnement (.env)

Créez un fichier `.env` à la racine (ou copiez `.env.example`) :

```env
# Configuration Base de données MySQL
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=ids_app
DB_PASSWORD=
DB_DATABASE=ids_ips_db

# Paramètres JWT
JWT_SECRET=super_secret_signing_key_change_me_in_prod
JWT_EXPIRATION=1h

# Paramètres API Wazuh (VM1)
WAZUH_API_URL=https://192.168.101.128:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=

# Port d'écoute du serveur
PORT=3000
```

---

## Instructions de Lancement

### 1. Prérequis
- Node.js (v18+)
- Serveur MySQL actif.
- Créer une base de données vide nommée : `ids_ips_db`.

### 2. Installation des dépendances
```bash
npm install
```

### 3. Lancement du serveur (Développement)
```bash
npm run start:dev
```
*Note: Au premier démarrage, les entités MySQL sont automatiquement générées en base de données grâce au mode `synchronize: true` de TypeORM.*

### 4. Comptes de Test Générés par défaut (Seeding)
Si la table `users` est vide lors du démarrage, le serveur insère automatiquement trois comptes de test :
- **Administrateur** : `admin` / `admin123`
- **Analyste** : `analyst` / `analyst123`
- **Lecteur (Viewer)** : `viewer` / `viewer123`

---

## Tests et Intégration API

Vous pouvez valider l'ensemble des endpoints en utilisant le fichier REST client [api-endpoints.http](api-endpoints.http) inclus à la racine du projet (idéal avec l'extension VS Code *REST Client*).

### Liste des principaux Endpoints :

| Méthode | Endpoint | Rôles Autorisés | Description |
| :--- | :--- | :--- | :--- |
| **POST** | `/auth/login` | Tout public | Authentification, retourne un JWT ou un `tempToken` MFA |
| **POST** | `/auth/mfa/setup` | Utilisateur authentifié | Génère le secret TOTP + QR code |
| **POST** | `/auth/mfa/setup/verify` | Utilisateur authentifié | Valide le code initial pour activer définitivement le MFA |
| **POST** | `/auth/mfa/verify` | Tout public (via tempToken) | Authentifie le jeton temporaire MFA et délivre le JWT final |
| **GET** | `/users/me` | Tout utilisateur connecté | Récupère le profil courant |
| **GET** | `/users` | `admin` | Liste tous les utilisateurs |
| **POST** | `/users` | `admin` | Crée un utilisateur |
| **GET** | `/alerts` | `admin`, `analyst` | Récupère les alertes Wazuh / Suricata avec filtres |
| **GET** | `/alerts/stats` | `admin`, `analyst`, `viewer` | Statistiques et agrégats pour graphiques dashboard |
| **GET** | `/agents/status` | `admin`, `analyst`, `viewer` | Statut des agents Wazuh |
| **POST** | `/reports/generate` | `admin`, `analyst` | Génère un document PDF ou Excel et retourne le flux |
| **GET** | `/reports/history` | `admin`, `analyst` | Historique MySQL des rapports générés |
| **GET** | `/audit-logs` | `admin` | Logs d'audit détaillés des actions sensibles |

---

## WebSocket & Temps Réel

Le serveur diffuse en continu des alertes via **Socket.io** sur le port `3000` du backend (par exemple `ws://<IP_VM1>:3000`).
- Événement émis : `new-alert`
- Intervalle : toutes les 5 secondes (simulé ou réel).
