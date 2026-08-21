# deepak-eventmanager

## Durable database setup

The app uses a Cloudflare Worker and Cloudflare D1. Browser `localStorage` remains as an offline cache, while the Worker stores the complete project state in D1.

### 1. Install Wrangler and log in

```bash
npm install -g wrangler
wrangler login
```

### 2. Create the D1 database

```bash
wrangler d1 create deepak-eventmanager
```

Copy the returned `database_id` into `wrangler.jsonc` in place of `REPLACE_WITH_YOUR_D1_DATABASE_ID`.

### 3. Apply the schema

```bash
wrangler d1 migrations apply deepak-eventmanager --remote
```

### 4. Configure Google login

Create a Google OAuth Web application in Google Cloud Console. Add this authorized redirect URI, replacing the domain with your deployed Worker URL:

```text
https://your-worker.workers.dev/api/auth/google/callback
```

Store the Google client ID and secret as Worker secrets. Never commit the secret.

```bash
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
```

Set the public site URL so the callback redirects correctly:

```bash
wrangler secret put SITE_URL
```

### 5. Deploy to Cloudflare Pages

```bash
wrangler pages deploy . --project-name deepak-eventmanager
```

In the Cloudflare Pages project, bind the D1 database as `DB` and add these Production environment variables:

```text
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
SITE_URL=https://deepak-eventmanager.pages.dev
```

Redeploy after adding the variables. Open the deployed site and create an account or choose **Continue with Google**. Each account has a private project workspace, protected by a secure HTTP-only session cookie. Every change is saved to D1 after a short delay, and the export button can be used for an additional backup.

### Local development

```bash
wrangler dev
```

The D1 database is durable, but keep periodic JSON exports or configure an external backup. A database service alone is not a backup strategy.