# KeyNest — Family Password Manager

A production-ready family password manager with role-based access control (RBAC),
bcrypt password hashing, Fernet encryption, TOTP MFA, SQLite database, admin
approval for new members, and full account management.

---

## Running locally

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

A default admin account is created on first run:
- Username: `admin`
- Password: `admin123`

Change this immediately after first login via **Change password** in the nav bar.

---

## Deploying online (Render.com — free tier)

1. Push this folder to a GitHub repository
2. Go to https://render.com and create a free account
3. Click **New → Web Service** and connect your GitHub repo
4. Set the following:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
   - Region: **Singapore** (closest to Australia)
5. Add these environment variables in Render's dashboard:

| Variable         | How to generate                                                                          |
|------------------|------------------------------------------------------------------------------------------|
| `SECRET_KEY`     | `python -c "import secrets; print(secrets.token_hex(32))"`                               |
| `ENCRYPTION_KEY` | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `ADMIN_CODE`     | Any string you choose — required to register new admin accounts                           |

6. Click **Deploy** — your app will be live at a `.onrender.com` URL

---

## Roles & permissions

| Permission           | Admin | Parent | Child |
|----------------------|-------|--------|-------|
| View own passwords   | ✓     | ✓      | ✓     |
| View all passwords   | ✓     | ✓      | ✗     |
| Add / edit own       | ✓     | ✓      | ✓     |
| Add / edit any       | ✓     | ✓      | ✗     |
| Delete any entry     | ✓     | ✗      | ✗     |
| Approve new members  | ✓     | ✗      | ✗     |
| Reset user passwords | ✓     | ✗      | ✗     |
| Manage members panel | ✓     | ✗      | ✗     |
| View audit log       | ✓     | ✓      | ✗     |

---

## Features

### Authentication
- Login with username and password (bcrypt verified)
- TOTP MFA via Google Authenticator or Authy — required for all users on every login
- First login redirects to MFA setup page — scan QR code or enter secret key manually
- Sessions expire after 30 minutes of inactivity

### Registration & admin approval
- New users submit a registration request with username, display name, password, and role
- The account is placed in a pending queue — the user cannot log in until an admin approves
- Admins see a **Pending approvals** panel (highlighted in amber) on their dashboard
- Each pending request shows the name, role, username, and time submitted
- Admins click **Approve** to create the account or **Reject** to remove the request
- Both actions are recorded in the audit log
- Admin accounts bypass the queue but require an invite code (`ADMIN_CODE` env variable)

### Vault
- Vault passwords are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256)
- Children can only see and manage their own entries
- Parents and admins can see all entries across the family
- Show / hide passwords on demand — each reveal is logged
- Copy password to clipboard
- Add, edit, and delete entries (permissions enforced server-side)

### Password generator
- Configurable character sets: uppercase, lowercase, numbers, symbols
- Adjustable length from 8 to 32 characters
- Uses `crypto.getRandomValues` — cryptographically secure randomness
- Live password strength indicator
- Generated password can be inserted directly into the add / edit form

### Account management
- **Change password** — any logged-in user can update their own master password
- **Delete account** — requires password confirmation and typing `DELETE` in capitals; the last admin account cannot be deleted
- **Admin: reset user password** — admin sets a temporary password for another user; forces MFA re-setup on their next login
- **Forgot password** — user contacts the family admin, who uses the Reset pw button in the members panel

### Audit log
- Every action is recorded server-side: logins, logouts, password views, vault edits, approvals, rejections, password resets
- Written inside Flask routes — cannot be forged or modified by clients
- Visible to admins and parents; hidden from children

---

## Security overview

| Feature                  | Detail                                                                        |
|--------------------------|-------------------------------------------------------------------------------|
| Master password storage  | bcrypt with automatic per-user salt — irreversible, defeats rainbow tables    |
| Vault encryption         | Fernet (AES-128-CBC + HMAC-SHA256) — unreadable without the encryption key   |
| MFA                      | TOTP via RFC 6238 — required for every role on every login                   |
| Transport security       | HTTPS / TLS provided automatically by Render                                 |
| Session management       | Server-side Flask sessions with 30-minute timeout                            |
| Permission enforcement   | All RBAC checks run server-side — cannot be bypassed from the browser        |
| Password generator       | Python `secrets` module backed by `os.urandom` — cryptographically secure    |
| Audit trail              | Server-written, database-stored, tamper-proof log of all access and changes  |
| Approval queue           | New members cannot access the vault until explicitly approved by an admin     |

---

## Project structure

```
keynest/
├── app.py                         # Flask app — models, RBAC, all routes
├── requirements.txt               # Python dependencies
├── Procfile                       # Deployment start command (Render / Railway)
├── README.md
└── templates/
    ├── login.html                 # Login page
    ├── register.html              # Registration request form
    ├── mfa_setup.html             # QR code / secret key setup
    ├── mfa_verify.html            # TOTP code entry on login
    ├── dashboard.html             # Main vault, pending approvals, members panel
    ├── change_password.html       # Change own master password
    ├── delete_account.html        # Delete own account with confirmation
    └── admin_reset_password.html  # Admin resets another user's password
```

---

## Key design decisions

**bcrypt for master passwords**
bcrypt is intentionally slow (cost factor 12), making brute-force attacks expensive.
The automatic salt means two users with the same password produce completely different
hashes, defeating rainbow table and credential stuffing attacks.

**Fernet for vault passwords**
Vault passwords must be recoverable (unlike master passwords), so hashing is not
suitable. Fernet provides authenticated symmetric encryption — if ciphertext is
tampered with, decryption fails. The encryption key is stored separately from the
database, so stealing the `.db` file alone is not enough to read vault contents.

**Server-side RBAC enforcement**
All permission checks run inside Flask route handlers. A child user cannot retrieve
another user's password by calling `/api/vault/<id>/password` directly — the server
checks the session role and returns HTTP 403 Forbidden if access is denied. The
frontend only reflects what the server enforces.

**Admin approval queue**
Without approval, anyone who finds the registration URL could create an account and
gain access to the family vault. The pending queue ensures only trusted family
members are admitted — with a full audit trail of who approved or rejected each request.

**TOTP MFA for all roles**
Since this is a password manager, every role is accessing sensitive credentials.
Requiring MFA uniformly means a stolen password alone is never sufficient to gain
access. TOTP (RFC 6238) is the same standard used by Google, GitHub, and most banks.
The `valid_window=1` parameter allows one 30-second window of clock drift, matching
standard authenticator app behaviour.

**Pending MFA re-setup after password reset**
When an admin resets a user's password, their MFA secret is also rotated. This
prevents a scenario where a compromised secret persists after a credential reset,
ensuring the reset is a genuine full re-authentication setup.
