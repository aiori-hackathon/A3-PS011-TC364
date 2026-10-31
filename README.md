# AIORI-3-HACKATHON-PROJECTS
This repository contains the complete implementation, presentation materials, and resources for the AIORI-3 Hackathon.

**Project:** ArgusTrace — Authorised Attack-Surface Inventory & Change Monitor  
**Hackathon:** AIORI Hackathon 3 — PS-011  
**Team:** VantaNex  
**YouTube Video Link:** https://youtu.be/_wlLSe1Hvmo  
**Presentation:** [A3-PS011-TC364_PPT.pdf](./A3-PS011-TC364_PPT.pdf)  
**Proposed Structure:** [Proposed-structure-hackathon.pdf](./Proposed-structure-hackathon.pdf)  
**Live Prototype:** https://argustrace-ps011-tc364.vercel.app/

---

# ArgusTrace — Authorised Attack-Surface Inventory & Change Monitor

**ArgusTrace** is an authorized attack-surface inventory, sequential baseline change detector, explainable risk classifier, alert/export engine, and automated recurring discovery monitor. Built for **PS-011 (Phases 1–6)**, it couples a hardened, ethical Python FastAPI discovery backend with a dark cybersecurity dashboard.

---

## 🛡️ Core Capabilities & Completed Phases (1–6)

### Phase 1: Authorized Asset Discovery & Initial Inventory
- **Explicit Authorisation & Scope Boundaries**: Scans require explicit confirmation (`authorised_confirmation=True`) and authorization metadata (`authorised_by`).
- **SSRF & Dangerous Range Prevention**: Blocks cloud metadata endpoints (`169.254.169.254`), private RFC 1918 ranges (unless Local Lab Mode is explicitly opted into), and redirect-chain SSRF.
- **Ethical Bounded Probes**: DNS queries (A, AAAA, CNAME, MX, NS, TXT, PTR), opt-in TCP port checks (Web, Standard, Extended presets), HTTP/HTTPS reachability headers, and TLS certificate inspection.

### Phase 2: Baseline Snapshots & Differential Asset Change Detection
- **Cryptographic Snapshots**: Generates immutable baselines for every completed scan.
- **Sequential Change Detection**: Computes delta across successive scans:
  - `ASSET_ADDED`: Newly observed attack surface targets.
  - `ASSET_REMOVED` & `INCONCLUSIVE`: Flags unreached targets with inconclusive handling.
  - `PORT_OPENED` / `PORT_CLOSED`: Delta tracking on network ports.
  - `DNS_CHANGED` / `HTTP_CHANGED` / `TLS_CHANGED`: Attribute shifts with full JSON diffs.

### Phase 3: Explainable Risk Classification & Vulnerability Surface
- **Deterministic Risk Rules**: Severity scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) based on exposed services (Telnet, unencrypted HTTP, deprecated TLS, exposed databases like MySQL 3306 or PostgreSQL 5432).
- **Explainable Rationale & Remediation**: Detailed rationales and remediation guidance for every finding.
- **Deduplication & Triage Workflow**: Deduplication keys prevent alert fatigue across repeated scans. Full triage workflow (`OPEN`, `IN_REVIEW`, `RESOLVED`, `ACCEPTED_RISK`).

### Phase 4: Security Analytics & Attack-Surface Posture Dashboard
- **Posture Score Metric**: Calculated attack-surface security posture with asset distribution by risk tier.
- **Timeline & Exposure Trends**: Sequential change velocity charts and risk distribution metrics.

### Phase 5: Alerts, Notifications, Reports & Audit Trail
- **Configurable Notification Rules**: Rules matching `ASSET_DISCOVERED`, `ASSET_CHANGED`, and `FINDING_DETECTED` with severity and change-type filters.
- **Safe Delivery Dispatcher**: External delivery disabled by default (`ENABLE_LIVE_NOTIFICATIONS=false`). Built-in SSRF protection blocking local/private webhook destinations, bounded retries (max 3), and hash-based event deduplication.
- **Sanitized Reports & Exports**: CSV and JSON exports for Inventory, Changes, and Findings with **CSV formula-injection mitigation** (prepends `'` to cells starting with `=`, `+`, `-`, `@`, `\t`, `\r`).
- **Immutable Audit Trail**: Structured event logging with automatic redaction of sensitive credentials and tokens.

### Phase 6: Automated & Scheduled Discovery
- **Recurring Scan Scheduling**: Frequency presets (`DAILY`, `WEEKLY`, `HOURLY_6`, `HOURLY_12`, and `CUSTOM` interval hours).
- **Strict Scope Authorization Enforcement**: Schedules can **only** be created for scopes with verified `authorised_confirmation = true`. Unconfirmed scopes are strictly rejected by the backend (`400 Bad Request`) and disabled in the UI.
- **Concurrency & Duplicate Execution Guardrails**: Prevents duplicate concurrent executions on the same scope (`409 Conflict` on manual trigger; auto-skip with `SKIPPED_CONCURRENT` status in the background scheduler).
- **Automatic Multi-Phase Integration**: Scheduled executions automatically run the complete pipeline: discovery engine -> baseline snapshot -> change detection -> risk classification -> notification dispatch -> audit logging.
- **Dedicated Scheduled Discovery UI**: Dashboard metrics, schedule toggle switches, on-demand "Run Now" triggers, and execution history modal.

---

## 📁 Repository Structure

```
A3-PS011-TC364/
├── A3-PS011-TC364_PPT.pdf         # Hackathon Presentation Slide Deck
├── Proposed-structure-hackathon.pdf # Hackathon Architecture Proposal
├── README.md                      # Primary Project Documentation
├── backend/
│   ├── app/
│   │   ├── config.py              # Settings, timeouts, port bounding, CORS
│   │   ├── database.py            # SQLite engine, migrations, SessionLocal
│   │   ├── main.py                # FastAPI app, scheduler worker, CORS
│   │   ├── models.py              # SQLAlchemy models (Phases 1-6)
│   │   ├── schemas.py             # Pydantic schemas (Phases 1-6)
│   │   ├── security.py            # SSRF guardrails, target validation
│   │   ├── discovery/             # Discovery engine, DNS, ports, HTTP, TLS
│   │   ├── routers/               # API endpoints (scopes, scans, findings, schedules, etc.)
│   │   └── services/              # Audit, export, notification, schedule services
│   ├── tests/                     # 40 automated unit & integration tests
│   ├── Dockerfile                 # Container build for backend hosting
│   ├── Procfile                   # PaaS process file (Render, Railway, Fly.io)
│   └── requirements.txt           # Python dependencies
└── frontend/
    ├── src/
    │   ├── api/                   # API client and TypeScript interfaces
    │   ├── components/            # UI components (inventory, discovery, schedules, reports)
    │   └── tests/                 # 23 Vitest unit & integration tests
    ├── vercel.json                # Vercel SPA routing configuration
    └── package.json               # Node.js dependencies & scripts
```

---

## 🧪 Verification & Test Results

### Backend Test Suite
```bash
cd backend
python -m pytest tests -v
# 40 passed, 0 failures (100% pass rate)
```

### Frontend Test Suite
```bash
cd frontend
npm test -- --run
# 23 passed across 7 test files (100% pass rate)
```

### Frontend Production Build & Lint
```bash
cd frontend
npm run build
# Built in 1.57s: dist/index.html, dist/assets/index-*.css, dist/assets/index-*.js
npm run lint
# 0 errors
```

---

## 🚀 Local Development Setup

### 1. Backend
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- API Docs: `http://127.0.0.1:8000/docs`
- Health Endpoint: `http://127.0.0.1:8000/api/health`

### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
- App UI: `http://localhost:5173`

---

## 🌐 Production Deployment

- **Frontend (Vercel)**:
  - Root directory: `frontend`
  - Framework: Vite
  - Build command: `npm run build`
  - Output directory: `dist`
  - Optional Environment Variable: `VITE_API_URL` (points to your live backend domain)
- **Backend (Render / Railway / Docker)**:
  - Build using `backend/Dockerfile` or `backend/Procfile`.
  - Exposes port 8000 with CORS configured for `*.vercel.app`.
