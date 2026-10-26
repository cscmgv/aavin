# Aavin Milk App (Frontend + Backend)

Zero dependencies - only Node.js 18+ needed (no `npm install`).

## Run locally
    ADMIN_PASSWORD=yourpass node server.js        # Windows: set ADMIN_PASSWORD=yourpass && node server.js
    open http://localhost:3000

If ADMIN_PASSWORD is not set, a random admin password is printed in the console on first run.

## Environment variables
| Name | Meaning |
|------|---------|
| ADMIN_PASSWORD | Admin login password (min 6 chars recommended). |
| DATA_DIR | Folder for db.json + daily backups. MUST be on a persistent disk. |
| PORT | Port (default 3000). |
| SECRET | Optional token-signing secret (auto-generated otherwise). |


## Storage: Supabase (recommended - no disk needed)
Data (customers, milk entries, deductions, payouts, recycle bin, PDF links) is stored in your Supabase Postgres.

1. Tables + functions are already created in the "Aavin" project (see `supabase/schema.sql` if you ever need to re-create them
   in a new project: Supabase -> SQL Editor -> paste -> Run).
2. Set these environment variables on the server (Render/Railway/VPS):

| Name | Value |
|------|-------|
| SUPABASE_URL | https://wkbqxeljtsrlaktsarsg.supabase.co |
| SUPABASE_SERVICE_KEY | the **service_role / secret** key: Supabase Dashboard -> Project Settings -> API Keys |
| ADMIN_PASSWORD | admin login password |

   Alternative without the service_role key ("token mode"): set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` (public key) and
   `APP_DB_TOKEN` (a long random secret whose SHA-256 is stored in `app_auth.token_hash`, see schema.sql). Do not set SUPABASE_SERVICE_KEY in that case.
3. Start: `node server.js` - the console prints `storage: Supabase`.

NEVER put the service_role key in the browser/app or in GitHub. It lives only in the server's environment variables.
RLS is enabled with no policies, so the public (anon) key cannot read or write any table.
If SUPABASE_URL / SUPABASE_SERVICE_KEY are not set, the server falls back to local files (DATA_DIR).

## Deploy on Vercel (works with Supabase)
The repo is Vercel-ready: `public/` is served as static files and `api/index.js` (rewrites in `vercel.json`) runs the backend as a Vercel Function.

1. Push this folder's contents to the GitHub repo root (server.js, api/, public/, vercel.json, package.json ...).
2. Vercel -> Add New -> Project -> import the repo. Framework preset: **Other**. No build command.
3. Environment Variables (Project Settings):
   - `SUPABASE_URL` = https://wkbqxeljtsrlaktsarsg.supabase.co
   - `SUPABASE_SERVICE_KEY` = service_role key (mark as **Sensitive**)
   - `ADMIN_PASSWORD` = admin password (mark as **Sensitive**)
4. Redeploy. Open the *.vercel.app link and log in as Admin.

Notes: Vercel needs Supabase (no writable disk). Every request reloads state from Supabase, so all instances stay consistent.
Request body limit on Vercel is 4.5 MB (a very large state save or PDF upload above that will fail).
Login brute-force lock is per function instance (Vercel may run several), so use a strong admin password.

## Deploy (examples)
* **VPS (cheapest, ~Rs.300-500/month)**: install Node 18+, copy this folder, run with pm2 
  (`pm2 start server.js`) and put Caddy/Nginx in front for HTTPS.
* **Render**: use render.yaml (free plan works with Supabase; the free service sleeps after inactivity and takes ~1 min to wake).
* **Railway / Fly.io**: add a Volume, set DATA_DIR to the volume path, set ADMIN_PASSWORD.
* **Docker**: `docker build -t aavin . && docker run -p 3000:3000 -v aavin-data:/data -e ADMIN_PASSWORD=xxx aavin`

Without Supabase, free hosting with an ephemeral disk will LOSE data on every restart - use Supabase or a persistent disk.
Download "Backup (JSON)" from the app regularly in either case.

## Security notes
* Passwords are stored as scrypt hashes. Customers log in with registered phone + password given by admin.
* A customer token can only read that customer's own records (`/api/me`). Everything else is admin-only.
* 5 wrong attempts => 5 minute lock. Use HTTPS in production (hosts like Render/Railway provide it).
* Daily backups are kept in DATA_DIR/backups (last 30).
