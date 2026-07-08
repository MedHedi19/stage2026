# VM Setup Commands for Backend

## Assumptions

- Run these commands on VM1 where NestJS, MySQL, and Wazuh are available.
- Use Ubuntu/Debian-style commands.
- Replace passwords before real use.
- Use the ngrok Wazuh URL instead of a direct VM IP.

## 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y curl git build-essential
```

## 2. Install Node.js 20

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v
npm -v
```

## 3. Install MySQL server

```bash
sudo apt install -y mysql-server
sudo mysql_secure_installation
```

Create the app database and user:

```bash
sudo mysql -u root -p
```

Then run:

```sql
CREATE DATABASE ids_ips_db;
CREATE USER 'ids_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON ids_ips_db.* TO 'ids_app'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

## 4. Clone the project

```bash
cd ~
git clone <YOUR_REPO_URL> backend
cd backend
```

## 5. Install dependencies

```bash
npm install
```

## 6. Create `.env`

```bash
cat > .env << 'EOF'
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=ids_app
DB_PASSWORD=CHANGE_ME_STRONG_PASSWORD
DB_DATABASE=ids_ips_db

JWT_SECRET=CHANGE_ME_JWT_SECRET
JWT_EXPIRATION=1h

WAZUH_API_URL=https://uselessly-glaucoma-velocity.ngrok-free.dev
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=CHANGE_ME_WAZUH_PASSWORD

PORT=3000
EOF
```

## 7. Run the backend

```bash
npm run start:dev
```

## 8. Quick validation

Check that the app listens on all interfaces:

```bash
ss -lntp | grep 3000
```

Check the MySQL tables:

```bash
mysql -u ids_app -p ids_ips_db -e "SHOW TABLES;"
```

## 9. Smoke test endpoints

From the same VM or from another machine, use the REST client file:

- `api-endpoints.http`

Main test flow:
- login as `admin`
- verify `/users/me`
- call `/alerts`
- call `/alerts/stats`
- call `/agents/status`
- generate a PDF or Excel report

## 10. Optional local test without direct VM IP

If you still need an external URL, use the ngrok endpoint for Wazuh only:

```env
WAZUH_API_URL=https://uselessly-glaucoma-velocity.ngrok-free.dev
```

Do not install Snort now; Suricata is enough for this stage.
