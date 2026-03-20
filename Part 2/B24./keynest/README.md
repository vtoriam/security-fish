# KeyNest — Family Password Manager

A production-ready family password manager with RBAC, bcrypt hashing,
Fernet encryption, TOTP MFA, SQLite database, and user registration.

## Running locally

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

A default admin account is created on first run:
- Username: admin
- Password: admin123
- Change this immediately after first login!

## Deploying online (Render.com — free tier)

1. Push this folder to a GitHub repository
2. Go to https://render.com and create a free account
3. Click "New" → "Web Service" → connect your GitHub repo
4. Set these settings:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
5. Add these environment variables in Render's dashboard:
   - `SECRET_KEY`     → any long random string (e.g. generate with: python -c "import secrets; print(secrets.token_hex(32))")
   - `ENCRYPTION_KEY` → run locally: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   - `ADMIN_CODE`     → your chosen invite code for creating admin accounts
6. Click "Deploy" — your app will be live at a .onrender.com URL

## Environment variables

| Variable        | Purpose                                      | Required in prod |
|-----------------|----------------------------------------------|-----------------|
| SECRET_KEY      | Flask session signing key                    | Yes             |
| ENCRYPTION_KEY  | Fernet key for encrypting vault passwords    | Yes             |
| ADMIN_CODE      | Invite code required to register as admin    | Yes             |
| DATABASE_URL    | Database connection (defaults to SQLite)     | No              |

## Security overview

- **bcrypt** — master passwords hashed with automatic per-user salt
- **Fernet encryption** — vault passwords encrypted at rest with AES-128-CBC + HMAC
- **TOTP MFA** — all users require authenticator app (RFC 6238)
- **Server-side RBAC** — all permission checks enforced in Flask routes
- **SQLite database** — persistent storage across restarts
- **Session timeout** — sessions expire after 30 minutes of inactivity
- **Audit log** — every action stored in database, cannot be forged

## Roles

| Permission       | Admin | Parent | Child |
|------------------|-------|--------|-------|
| View own         | ✓     | ✓      | ✓     |
| View all         | ✓     | ✓      | ✗     |
| Add/edit own     | ✓     | ✓      | ✓     |
| Add/edit any     | ✓     | ✓      | ✗     |
| Delete any       | ✓     | ✗      | ✗     |
| Manage members   | ✓     | ✗      | ✗     |
| View audit log   | ✓     | ✓      | ✗     |

## Project structure

```
keynest/
├── app.py                   # Flask app, models, RBAC, all routes
├── requirements.txt
├── Procfile                 # For Render/Railway deployment
├── README.md
└── templates/
    ├── login.html
    ├── register.html
    ├── mfa_setup.html
    ├── mfa_verify.html
    ├── change_password.html
    └── dashboard.html
```
