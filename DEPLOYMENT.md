# Mission-Haiti Deployment Checklist

The local app works, but sponsor email links currently point to `127.0.0.1`, which only works on Paul's Mac. To let sponsors open links from their own devices, deploy the app and set `APP_BASE_URL` to the live HTTPS address.

## Recommended MVP Host

Use Render, Railway, Fly.io, or a VPS that supports:

- Python web service
- HTTPS
- persistent disk or volume
- environment variables

For this current MVP, choose a host with a persistent disk. SQLite and private uploads must not live on temporary storage.

## Start Command

```bash
HOST=0.0.0.0 python3 app.py
```

The host will provide `PORT` automatically.

## Environment Variables

Set these in the host dashboard:

```env
APP_BASE_URL=https://updates.mission-haiti.org
DATA_DIR=/var/data
SESSION_SECRET=replace-with-a-new-long-random-secret

SMTP_HOST=smtp.postmarkapp.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_USERNAME=your-postmark-token
SMTP_PASSWORD=your-postmark-token
SMTP_FROM_EMAIL=paul@mission-haiti.org
SMTP_FROM_NAME=Mission-Haiti
```

Use the real deployed URL for `APP_BASE_URL`. If the domain is not ready yet, use the temporary HTTPS URL from the host first.

## Persistent Disk

Mount the persistent disk at:

```text
/var/data
```

The app will store the SQLite database and private uploads there when `DATA_DIR=/var/data`.

## Domain

After the app is deployed:

1. Add `updates.mission-haiti.org` as a custom domain in the hosting dashboard.
2. Add the DNS record requested by the host.
3. Wait for HTTPS to become active.
4. Change `APP_BASE_URL` to `https://updates.mission-haiti.org`.
5. Restart/redeploy the app.

## Post-Deployment Test

1. Log in as admin.
2. Create or open an approved update.
3. Click **Resend to sponsors**.
4. Open the sponsor email on a phone or another computer.
5. Confirm the link opens the live HTTPS site.
6. Log in as the sponsor and confirm only linked students are visible.
