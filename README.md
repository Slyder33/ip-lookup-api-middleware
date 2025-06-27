# 📦 Email Header Sleuth Middleware (Docker + Render)

This repo contains a Flask API that analyzes email headers for spoofing, phishing, and suspicious signals.

## 🐳 Docker Quickstart
1. Clone the repo and build the container locally (optional):
```bash
docker build -t header-sleuth .
docker run -p 5000:5000 header-sleuth
```

## 🚀 Deploy to Render
1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com/)
3. Click **New Web Service**
4. Connect GitHub → Select your repo
5. Choose "Docker" as environment
6. Set PORT environment variable: `5000`
7. Add secret `GOOGLE_SAFE_BROWSING_KEY`
8. Click Deploy

## 🧪 Test API Endpoint
Send a POST request with a raw email header:
```bash
curl -X POST https://your-render-url.onrender.com/ \
  -H "Content-Type: application/json" \
  -d '{"header": "<paste raw header here>"}'
```
