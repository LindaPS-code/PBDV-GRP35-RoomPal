# Deployment Notes

## Recommended host

Use Render for this project.

Reasons:
- This app is a long-running Flask server with SQLAlchemy and server-rendered templates.
- Render supports standard Python web services with `gunicorn`.
- Render also provides PostgreSQL and optional persistent disks for uploaded files.

## Why not Vercel first

Vercel can run Python, but it is a function-oriented platform and is a less natural fit for this full Flask app.

## Render setup

1. Push this project to GitHub.
2. In Render, create a new Blueprint or Web Service.
3. If using the dashboard manually:
   Build command: `pip install -r requirements.txt`
   Start command: `gunicorn wsgi:app`
4. Create a PostgreSQL database and set `DATABASE_URL`.
5. Set `SECRET_KEY`.
6. Add Brevo SMTP variables if you want real emails.
7. If you need uploaded files to persist, set `UPLOAD_FOLDER` and `EMAIL_PREVIEW_FOLDER` to a persistent disk path.

## Important storage note

This app supports file uploads. On hosted platforms, local disk may be ephemeral.

For a demo:
- Render + PostgreSQL is enough for database-backed features.
- If you need uploaded images to survive redeploys, use a Render persistent disk or move uploads to object storage.

Example persistent-disk values:
- `UPLOAD_FOLDER=/var/data/uploads`
- `EMAIL_PREVIEW_FOLDER=/var/data/sent_emails`

## Optional demo admin

If you want Render to create a starter admin account on first boot, set:

- `SEED_DEFAULT_ADMIN=true`
- `ADMIN_USERNAME`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
