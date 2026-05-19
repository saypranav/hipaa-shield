# HIPAA Shield

A HIPAA compliance auditing dashboard. A FastAPI backend orchestrates external security scanners (nmap, nikto, trufflehog, source SAST) plus OpenMRS / MySQL log analyzers, maps findings to 45 CFR Part 160/164 citations, and surfaces them in a React dashboard. A Gemini-powered chat advisor answers compliance questions using BGE-M3 hybrid retrieval over the HIPAA reference text stored in a local Qdrant index.

## Architecture

- **Backend** — `hipaa_dashboard/backend/` — FastAPI on `:8000`. Runs scanners as subprocesses, streams logs, analyzes them against HIPAA keywords, exposes `/scan/<id>`, `/scan/<id>/status`, `/report`, `/chat`, `/upload-policy`.
- **Frontend** — `hipaa_dashboard/frontend/index.html` — single-file React (CDN + Babel standalone), no build step. Polls the backend every 2–3s.
- **Retrieval** — `ingest_hipaa.py` chunks `part160.txt` + `part164.txt` and indexes them into a local Qdrant collection at `./qdrant_data/`. Chatbot uses dense + sparse hybrid search.
- **Default scan target** — `http://localhost:9901` (intended for a local OpenMRS instance). Change in the dashboard nav (admin role only).

## Prerequisites

System tools — required for the scanner cards to function:

```sh
brew install python@3.12 nmap nikto trufflehog
```

## Setup

```sh
git clone https://github.com/saypranav/hipaa-shield.git
cd hipaa-shield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`FlagEmbedding` pulls in PyTorch (~few hundred MB); first install is slow.

## Configuration

Create `hipaa_dashboard/backend/.env` (gitignored):

```
GEMINI_API_KEY=<get one at https://aistudio.google.com/apikey>
```

## Build the HIPAA vector index (one-time)

```sh
python ingest_hipaa.py
```

First run downloads the BGE-M3 embedding model (~2 GB) and writes the index to `./qdrant_data/`. Re-run only if `part160.txt` / `part164.txt` change.

## Run

Backend:

```sh
uvicorn hipaa_dashboard.backend.main:app --port 8000 --reload
```

Health check: `curl http://localhost:8000/scan/nmap/status` → `{"status":"idle","logs":[]}`.

Frontend — open `hipaa_dashboard/frontend/index.html` directly, or serve it over HTTP (recommended, so `window.open` works reliably):

```sh
python -m http.server 5500 --directory hipaa_dashboard/frontend
# then visit http://localhost:5500
```

## Using the dashboard

1. Pick a role on the login screen. **Engineer** or **Admin** can run scans; **Auditor** is read-only.
2. Click **Run Scan** on any card, or **Run System Audit** to launch all of them. Results open in a new tab and stream logs in real time.
3. Upload a PDF in the **Security Policy** card — lands in `hipaa_dashboard/backend/uploads/policies/`.
4. Chat with the Advisor sidebar — retrieves HIPAA chunks from Qdrant and answers via Gemini.

## Repo layout

```
hipaa_dashboard/
  backend/         # FastAPI app, scanners, analyzer, chatbot
  frontend/        # index.html (React via CDN)
build_chunks.py    # HIPAA text chunking utilities
ingest_hipaa.py    # Builds the local Qdrant index
synthea_to_openmrs.py
part160.txt, part164.txt
45 CFR Part 16{0,4}*.pdf   # source documents
docs/plans/        # design notes
```

## Notes

- `openmrs-hospital/` (the scan target) is excluded from this repo. Run it separately or point the dashboard at a different authorized target.
- The dashboard is for authorized auditing only. Running these scanners against systems you do not own or have written permission to test may be illegal.
