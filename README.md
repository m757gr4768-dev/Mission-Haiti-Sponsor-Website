# Mission-Haiti Sponsor Updates MVP

A secure, low-cost MVP for staff in Haiti to share student updates with U.S. sponsors.

## Architecture

- Server-rendered web app for simple deployment and strong mobile support.
- SQLite database for MVP data.
- Private upload storage under `data/uploads/private`.
- All uploaded media and report cards are served through `/files/<id>`, which checks the logged-in user's permissions before returning a file.
- Role-based access:
  - Admins manage students, sponsors, review updates, and approve updates.
  - Haiti staff create student updates and submit drafts for review.
  - Sponsors can only see active students linked to them and approved updates.
- Email notifications are written to an audit table and sent through SMTP when configured. If SMTP is not configured, the app records the notification as `skipped` so local testing is still safe.

## Recommended Production Stack

For a real deployment after this MVP, use:

- Django + Postgres
- S3-compatible private object storage, such as AWS S3 or Cloudflare R2
- Signed file access through the app, not public bucket URLs
- Postmark, AWS SES, or SendGrid for email
- Render, Fly.io, Railway, or a small VPS for hosting

This prototype intentionally avoids third-party dependencies so it can run locally in this workspace.

## Database Schema

- `users`: login identity, email, password hash, role, linked sponsor id
- `students`: name, school, grade level, profile photo file id, active flag
- `sponsors`: sponsor name, email, linked user id
- `sponsor_students`: many-to-many relationship between sponsors and students
- `updates`: note, status, author, approver, timestamps
- `update_files`: private file attachments for profile photos, report cards, photos, and videos
- `email_notifications`: approval email audit/outbox

## Routes

- `/login`
- `/logout`
- `/dashboard`
- `/students`
- `/students/new`
- `/students/<id>`
- `/students/<id>/edit`
- `/sponsors`
- `/sponsors/new`
- `/sponsors/<id>/edit`
- `/admins`
- `/updates/new`
- `/updates/<id>`
- `/updates/<id>/submit`
- `/updates/<id>/approve`
- `/updates/<id>/resend`
- `/portal/students/<id>`
- `/files/<id>`

## Demo Accounts

The app seeds these users on first run:

- Admin: `admin@mission-haiti.local` / `admin123`
- Haiti staff: `staff@mission-haiti.local` / `staff123`
- Sponsor: `sponsor@example.com` / `sponsor123`

## Run

```bash
/Users/Paul/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 app.py
```

Then open `http://127.0.0.1:8000`.

## Deploy

See `DEPLOYMENT.md`.

For deployment, the app supports:

- `HOST=0.0.0.0` so a hosting service can serve public traffic.
- `PORT`, which the host usually provides automatically.
- `DATA_DIR=/var/data` or another persistent disk path for the database and private uploads.
- `APP_BASE_URL=https://your-live-domain` so email links point to the real sponsor portal.

## Real Email Setup

The app sends real email through SMTP when these settings exist in `.env`.

1. Copy `.env.example` to `.env`.
2. Fill in your SMTP provider settings.
3. Set `APP_BASE_URL` to the real app URL when deployed.
4. Restart the app.

Approval behavior:

- If SMTP is configured correctly, approval sends the sponsor an email and records status `sent`.
- If SMTP is missing, approval records status `skipped`.
- If SMTP fails, approval records status `failed` with the error message.

Recommended providers:

- Postmark for easiest nonprofit/product-style transactional email.
- SendGrid if you already use it.
- Amazon SES for low cost at production scale.
