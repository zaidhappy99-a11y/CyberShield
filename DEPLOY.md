# Deploy CyberShield + NetSentinel (free, normal https link)

This deploys `backend_server.py` on Render's free tier. You get a
link like `https://cybershield-xyz.onrender.com`.

> Note: free Render services sleep after ~15 minutes idle. First visit
> after sleeping takes ~30–60 seconds while it wakes up.

## Steps (about 3 minutes)

1. Open https://render.com and sign up (free, Google login is fine).
2. Click **New** → **Web Service** (not Blueprint).
3. Choose **Deploy from a public Git repository** and push this project
   to GitHub first (or use **Upload** if offered), then select the repo.
4. Fill in:
   - **Name:** pick anything, e.g. `cybershield` (this becomes your URL)
   - **Region:** Singapore (closest)
   - **Branch:** main
   - **Runtime:** Python
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python backend_server.py`
5. Environment variables — nothing required (the server falls back to
   demo data if the Java detector isn't running).
6. Click **Create Web Service**. Wait for "Live".
7. Open your new URL — same flow: landing → Register/Login → NetSentinel at `/app/`.

## Alternative free hosts (same start command)

- **Railway:** `python backend_server.py`, set `PORT` (Railway provides it).
- **Fly.io:** `fly launch`, set the internal port to 8080.
- **Render** is the easiest for a first deploy.

## What NOT to do

- Don't rely on tunnel links (`serveo`, `ngrok`, `localhost.run`) as your
  "normal website" — the URL changes on every restart, requires your PC
  to stay on, and school/work filters flag tunnel domains as Phishing
  (that's why the serveo link got blocked).
- A Render/railway deploy stays online without your PC.
