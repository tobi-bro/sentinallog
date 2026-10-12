# SentinelLog — Deployment & Execution Guide

**Document Version:** 1.0.0  
**Application Version:** 2.4.0  

---

## 1. Local Deployment (Windows PowerShell)

### Prerequisites:
- Python 3.12+ (or 3.14)
- Git for Windows

### Setup Steps:
```powershell
# 1. Clone the repository
git clone https://github.com/tobi-bro/sentinellog.git
cd sentinellog

# 2. Create and activate virtual environment
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run CLI Interactive Mode
python main.py

# 5. Or launch the Web Dashboard & REST API
python main.py --web --port 8000
```
Open your browser to `http://127.0.0.1:8000` to access the SOC Investigation Dashboard, or `http://127.0.0.1:8000/docs` for interactive OpenAPI Swagger documentation.

---

## 2. Docker Container Deployment

SentinelLog includes a secure, non-root, hardened Docker container based on `python:3.12-slim`.

### Build the Image:
```bash
docker build -t sentinellog:2.4.0 .
```

### Run the Container:
```bash
docker run -d \
  --name sentinellog \
  -p 8000:8000 \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  sentinellog:2.4.0
```

### Verify Container Health:
```bash
docker ps
# Inspect status: Status will show (healthy)
```

---

## 3. Minimal Cloud Deployment

For cost-effective demonstration, SentinelLog can be hosted on free or low-cost container environments:
- **Render / Railway / Fly.io:** Deploy directly using the provided `Dockerfile` with port 8000.
- **AWS App Runner / Google Cloud Run:** Serverless container deployment with automatic TLS termination and zero idle resource usage.
