# Blog Management System

A production-style blog platform built with **Flask** — featuring dual-auth (Google OAuth 2.0 + email/password), Cloudinary-based media storage, a rich text editor, and a full comment/category system. Deployed on Render.

**Live Demo:** https://blog-management-system-d8hn.onrender.com/

---

## Architecture

```
┌────────────────────────────────────────────────────┐
│                  Browser (Client)                  │
│         Bootstrap UI · TinyMCE Editor              │
└────────────────┬───────────────────────────────────┘
                 │ HTTP
┌────────────────▼───────────────────────────────────┐
│              Flask Application                     │
│                                                    │
│  ┌─────────────┐   ┌──────────────┐               │
│  │  Auth Layer │   │ Route Layer  │               │
│  │             │   │              │               │
│  │ Local Auth  │   │ /posts       │               │
│  │ (Flask-Login│   │ /auth        │               │
│  │  + bcrypt)  │   │ /comments    │               │
│  │             │   │ /profile     │               │
│  │ Google OAuth│   │ /categories  │               │
│  │  2.0 Flow   │   └──────┬───────┘               │
│  └──────┬──────┘          │                       │
│         │        ┌────────▼──────────┐            │
│         └───────►│  SQLAlchemy ORM   │            │
│                  │  User · Post      │            │
│                  │  Comment · Category│           │
│                  └────────┬──────────┘            │
└───────────────────────────┼────────────────────────┘
                            │
           ┌────────────────┼──────────────────┐
           │                │                  │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌───────▼──────┐
    │   SQLite    │  │  Cloudinary │  │ Google OAuth  │
    │  (dev DB)   │  │  (images)   │  │   Provider    │
    └─────────────┘  └─────────────┘  └──────────────┘
```

### Auth Flow — Google OAuth 2.0

```
User clicks "Login with Google"
        │
        ▼
Flask redirects → Google OAuth consent screen
        │
        ▼ (authorization code)
Flask /oauth-callback
        │
        ▼
Exchange code → access token → fetch Google profile
        │
        ▼
Upsert User record (google_id + email)
        │
        ▼
Flask-Login session created → redirect to dashboard
```

---

## Features

- **Authentication** — Email/password (bcrypt-hashed) + Google OAuth 2.0 via Flask-Login
- **Rich content** — TinyMCE editor with full formatting, embedded images
- **Media uploads** — Cloudinary integration for post images and profile avatars
- **Comments & Categories** — Comment system with category-based filtering and post view tracking
- **Responsive UI** — Bootstrap layout, mobile-friendly
- **Schema migrations** — Flask-Migrate (Alembic) for iterative schema changes

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Flask, Jinja2, Flask-Login, Flask-Migrate |
| Database | SQLite (dev) / SQLAlchemy ORM |
| Auth | Email/password + Google OAuth 2.0 |
| Storage | Cloudinary (images + avatars) |
| Editor | TinyMCE |
| Deployment | Render |

---

## Local Setup

### 1. Clone and install

```bash
git clone https://github.com/Ishika1435/blog-management-system
cd blog-management-system
pip install -r requirements.txt
```

### 2. Configure environment

Create `.env` in the project root:

```env
SECRET_KEY=your_secret_key
CLOUDINARY_URL=cloudinary://api_key:api_secret@cloud_name
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### 3. Run migrations and start

```bash
flask db upgrade
python index.py
# App at http://localhost:5000
```

---

## Project Structure

```
blog-management-system/
├── index.py              # App entry point + all routes
├── instance/
│   └── blog.db           # SQLite database (dev only)
├── migrations/           # Flask-Migrate / Alembic migrations
│   └── versions/         # Schema version history
├── templates/            # Jinja2 HTML templates
├── static/               # CSS, JS, assets
└── requirements.txt
```

---

## Engineering Notes

**Dual-auth without conflicts** — Local and OAuth sessions both flow through Flask-Login's `current_user`. The key was a unified `User` model with nullable `google_id` and `password_hash` fields, allowing either auth path to resolve to the same session abstraction.

**Schema evolution** — Used Flask-Migrate throughout development. Migration files in `versions/` show the full schema history: initial user/post models → added Google OAuth fields → comments → view tracking.

**Cloudinary integration** — Images are uploaded via the Cloudinary Python SDK on the server side (not client-side direct upload). This keeps API secrets off the client and allows server-side validation before storage.

---

## License

MIT
