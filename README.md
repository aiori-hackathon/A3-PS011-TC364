# ArgusTrace — Attack Surface Asset Discovery (PS-011 Phase 1 Prototype)

**ArgusTrace** is an authorized attack-surface asset discovery and initial inventory platform designed strictly for **Phase 1 (PS-011)**. It provides a distinctive, premium cybersecurity dashboard coupled with a hardened, ethical Python FastAPI discovery engine.

---

## 🛡️ Phase 1 Core Capabilities & Guardrails

- **Explicit Authorisation & Scope Boundaries**:
  - Requires explicit confirmation (`authorised_confirmation=True`) and authorization metadata (`authorised_by`) before any scan can be scheduled or executed.
  - Strict input validation rejecting wildcards (`*.example.com`), control characters, command injection patterns, and malformed strings.
- **SSRF & Dangerous Range Prevention**:
  - **Cloud Metadata Protection**: Permanently blocks cloud metadata endpoints (e.g. `169.254.169.254`, `fd00:ec2::254`) regardless of mode.
  - **Local Lab Guard**: Blocks loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and private RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) by default. These are accessible only if the user explicitly enables "Local Lab Mode" on the authorized scope.
  - **Redirect SSRF Shield**: HTTP probes inspect and validate redirect locations at every hop; redirects pointing toward prohibited IP ranges or metadata endpoints are blocked immediately.
- **Ethical Discovery Probes (Non-Destructive & Bounded)**:
  - **DNS Lookups**: Comprehensive queries for `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and reverse `PTR` records.
  - **Bounded TCP Checks**: Opt-in port probing restricted to configurable allowlists (presets: Web 80/443; Standard 11 ports; Extended 19 ports; or Custom CSV capped at 50 max).
  - **HTTP/HTTPS Reachability**: Basic response metadata including status code, server header, HTML title, content-type, latency (ms), and redirect chains.
  - **TLS Certificate Inspector**: Extracts subject CN/organization, issuer authority, validity window, days remaining before expiry, SANs, cipher suite, and protocol version.
- **Guardrails Strictly Observed**:
  - No stealth scanning, no vulnerability exploitation, no brute force, no credential attacks, and no unrestricted port sweeps.
  - No scans execute automatically on startup.
  - Real discovery results only (no fabricated entries).
  - Optional visibly-labeled Demo Mode (`[DEMO / SYNTHETIC]`) with synthetic lab data for offline demonstration.
- **Persisted SQLite Inventory**:
  - Relational schema (Scopes, Scan Runs, Discovered Assets, Scan Findings) with indexes and foreign key cascades.

---

## 📁 Project Structure

```
d:/ARGUSTRACE/
├── backend/
│   ├── app/
│   │   ├── config.py              # App settings, timeouts, port bounding, CORS
│   │   ├── database.py            # SQLite engine, SessionLocal, Base
│   │   ├── main.py                # FastAPI app, lifespan, CORS, error handling
│   │   ├── models.py              # SQLAlchemy models (Scope, ScanRun, DiscoveredAsset, ScanFinding)
│   │   ├── schemas.py             # Pydantic schemas with ConfigDict
│   │   ├── security.py            # SSRF protection, target validation, IP classification
│   │   ├── discovery/
│   │   │   ├── dns_resolver.py    # DNS lookups (A, AAAA, CNAME, MX, NS, TXT, PTR)
│   │   │   ├── port_scanner.py    # Bounded non-destructive TCP port checker
│   │   │   ├── http_probe.py      # HTTP/HTTPS probe with SSRF-safe redirect validation
│   │   │   ├── tls_inspector.py   # TLS certificate inspector & expiry calculator
│   │   │   └── engine.py          # Background discovery coordinator with cancellation
│   │   └── routers/
│   │       ├── health.py          # /api/health endpoint
│   │       ├── scopes.py          # /api/scopes CRUD & /validate-targets endpoint
│   │       ├── scans.py           # /api/scans launch, status, cancellation & findings
│   │       ├── assets.py          # /api/assets inventory, filters & detail inspection
│   │       └── stats.py           # /api/stats/overview & /api/demo seed/clear
│   ├── tests/
│   │   ├── test_security.py       # SSRF guardrail, wildcard & IP bounding tests
│   │   └── test_api.py            # API integration tests (health, scopes, scans, demo)
│   ├── pytest.ini                 # Pytest configuration
│   ├── requirements.txt           # Python backend dependencies
│   └── .env.example               # Environment variables template
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── client.ts          # Typed REST API client
│   │   │   └── types.ts           # TypeScript interfaces
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.tsx    # Cyber navigation bar with demo indicator
│   │   │   │   └── Header.tsx     # View headers, health status, quick actions
│   │   │   ├── ui/
│   │   │   │   ├── Badge.tsx      # Status badges with pulse effects
│   │   │   │   ├── Button.tsx     # Cyan glow buttons with loading states
│   │   │   │   ├── Card.tsx       # Cyber glassmorphic panel
│   │   │   │   ├── Drawer.tsx     # Slide-over Asset Detail Drawer
│   │   │   │   └── Modal.tsx      # Dialog modal
│   │   │   ├── overview/
│   │   │   │   └── OverviewView.tsx # Metrics, asset categories, top services
│   │   │   ├── inventory/
│   │   │   │   ├── InventoryView.tsx # Search, multi-filters, asset table
│   │   │   │   └── AssetDetailDrawer.tsx # DNS, HTTP, TLS, and Evidence tabs
│   │   │   ├── discovery/
│   │   │   │   ├── DiscoveryView.tsx # Radar monitor, progress %, console logs
│   │   │   │   └── NewScanModal.tsx  # Bounded port presets & scope selector
│   │   │   └── scope/
│   │   │       ├── ScopeView.tsx     # Scopes list & management
│   │   │       └── ScopeModal.tsx    # Real-time target validation & consent
│   │   ├── tests/
│   │   │   ├── client.test.ts     # Frontend API client tests
│   │   │   └── components.test.tsx# UI component tests
│   │   ├── App.tsx                # Main view router & scan polling coordinator
│   │   ├── index.css              # Cyber grid styling, animations & theme
│   │   └── main.tsx               # React DOM entry point
│   ├── index.html                 # App shell with JetBrains Mono font
│   ├── package.json               # Node.js dependencies & scripts
│   ├── tailwind.config.js         # Midnight navy, electric cyan, and violet theme
│   ├── vite.config.ts             # Vite dev server with /api proxy
│   └── vitest.config.ts           # Vitest configuration
└── README.md
```

---

## ⚡ Windows PowerShell Setup & Run Instructions

### 1. Prerequisites
- **Python**: 3.12+ (verified on Python 3.12.10)
- **Node.js**: v20+ (verified on Node.js v24.18.0)
- **PowerShell**: Windows PowerShell or PowerShell 7

---

### 2. Backend Installation & Startup

Open a PowerShell terminal and run:

```powershell
# Navigate to the backend directory
cd d:\ARGUSTRACE\backend

# (Optional) Create and activate a Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt

# Start the FastAPI backend server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend API will start at:
- **API Base**: `http://127.0.0.1:8000/api`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Health Check**: `http://127.0.0.1:8000/api/health`

---

### 3. Frontend Installation & Startup

Open a **second** PowerShell terminal and run:

```powershell
# Navigate to the frontend directory
cd d:\ARGUSTRACE\frontend

# Install node dependencies
npm install

# Start the Vite development server
npm run dev
```

Open your browser at **`http://localhost:5173`**.

---

## 🧪 Testing & Verification Commands

### Run Backend Test Suite (Pytest)
In your backend terminal:
```powershell
cd d:\ARGUSTRACE\backend
python -m pytest -v
```
**Results**:
- 13 passed in 1.26s
  - `test_health_check`
  - `test_target_validation_endpoint`
  - `test_scope_creation_authorization_required`
  - `test_scope_creation_and_listing`
  - `test_scan_launch_requires_authorised_scope`
  - `test_demo_seed_and_overview`
  - `test_sanitize_target_input`
  - `test_target_wildcards_blocked`
  - `test_cloud_metadata_blocked`
  - `test_private_ip_guardrails`
  - `test_loopback_guardrails`
  - `test_valid_domain_validation`
  - `test_port_list_bounding`

### Run Frontend Type Checks, Build, and Unit Tests
In your frontend terminal:
```powershell
cd d:\ARGUSTRACE\frontend

# Run unit tests with Vitest
npm run test

# Run TypeScript compilation and production build
npm run build
```
**Results**:
- `npm run test`: 6 passed across 2 test files (`client.test.ts`, `components.test.tsx`)
- `npm run build`: Zero errors, 1,969 modules transformed, complete static bundle built into `dist/`.

---

## 🚀 Live Demonstration Walkthrough

1. **First-Run Empty State**:
   - On opening `http://localhost:5173`, the Overview displays guided onboarding with 3 clear steps.
2. **Offline / Demo Mode**:
   - Click **"Load Demo Sample Data"** in the sidebar.
   - Instantly ingests an explicitly labeled authorized lab scope with 5 simulated assets (`portal.demo-corp.internal`, `api.demo-corp.internal`, `vpn.demo-corp.internal`, `mail.demo-corp.internal`, `192.168.10.45`).
   - Notice the prominent `[SYNTHETIC DEMO DATA]` badge ensuring no confusion with live targets.
3. **Asset Inventory Exploration**:
   - Switch to **Asset Inventory**.
   - Filter by port (e.g. `Port 443`), status (`ACTIVE`), or search by domain keyword.
   - Click any asset row to open the **Slide-out Detail Drawer**:
     - **DNS Tab**: Inspect A, AAAA, MX, TXT records.
     - **HTTP Tab**: Inspect status code (200 OK, 403), Server header (`nginx/1.24.0`, `envoy`), latency, and redirect chain.
     - **TLS Tab**: Review certificate subject CN, issuer, expiry meter (e.g. 84 days remaining), and SANs.
     - **Findings Tab**: Review raw JSON audit evidence.
4. **Creating a Real Authorized Scope**:
   - Go to **Scope Settings** -> **Add Scope**.
   - Type target hosts (e.g. `example.com`).
   - Notice the live target validation running in real time: wildcards like `*.com` or cloud metadata `169.254.169.254` are flagged and rejected immediately.
   - Check the mandatory confirmation checkbox and submit.
5. **Running a Live Manual Discovery**:
   - Go to **Discovery Runs** -> **New Discovery Run** (or click **Launch Scan**).
   - Select your scope, choose port preset (Web 80/443 or Standard), and launch.
   - Watch the animated radar monitor, progress bar, and real-time streaming console logs as probes execute safely.
   - Hit **Cancel Discovery Run** anytime to verify safe cancellation.

---

## 🔒 Scope & Limitations (Phase 1 Prototype)
- **Phase 1 Only**: Strictly limited to authorized asset discovery and initial inventory.
- Does **not** include Phase 2+ features (automated periodic cron scans, continuous alerting, vulnerability exploitation, CVE scanning, or diff reporting).
