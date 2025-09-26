# Deep_K — FastAPI App (Cleaned for Deployment)

This is a cleaned version of your project, ready to push to GitHub and deploy on Render/Railway.

## Project Layout
```
.
├─ backend/
│  ├─ app.py                # FastAPI app (entrypoint: backend.app:app)
│  └─ ...                   # your existing backend files
├─ frontend/
│  └─ index.html            # static client (optional)
├─ requirements.txt
├─ Procfile                 # start command for hosts
├─ .env.example             # document env vars
└─ .gitignore
```

> **Do not commit `.env` or real secrets.** Use `.env.example` as a template and set the real values in the host dashboard.

## 1) Push to GitHub
```bash
git init
git add .
git commit -m "Initial cleaned deploy"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

## 2) Deploy on Render
1. Create an account on Render and click **New + → Web Service**.
2. Connect your GitHub repo.
3. Environment: `Python`
4. Build Command (Render autodetects; if needed): `pip install -r requirements.txt`
5. Start Command: `uvicorn backend.app:app --host 0.0.0.0 --port $PORT`
6. Add Environment Variables (from `.env.example`). **Don’t paste them in code**.
7. Deploy.

## 3) Deploy on Railway (alternative)
1. New Project → **Deploy from GitHub** (select this repo).
2. Add the same Environment Variables.
3. Start Command: `uvicorn backend.app:app --host 0.0.0.0 --port $PORT`

## 4) Local run
```bash
python -m pip install -r requirements.txt
# Set env vars in your shell, or create a local .env and export them before run
uvicorn backend.app:app --reload
```

### Notes
- Your app uses **FastAPI**, **JWT**, **S3**, and **AES-GCM** encryption. Make sure `S3_BUCKET_NAME`, `AWS_*` keys, and `JWT_SECRET` are set.
- If you have CORS issues for the frontend, add your site origin to the CORS allow list in `backend/app.py`.
- Avoid committing `users.db` or encrypted local files. They’re excluded via `.gitignore`.
