# PhishGuard Enterprise Browser Security Hub & Chrome Extension

An enterprise-grade browser security monitoring and threat interception system connecting multiple Chrome Extension installations to a central security server, real-time deterministic decision engine, and administrative SOC console.

---

## 1. System Architecture

```
┌────────────────────────────────────────────────────────┐
│               Chrome Extension Fleet                   │
│   (Workstations, Laptops, Remote Endpoints)            │
│                                                        │
│  • Service Worker (background.js, Manifest V3)         │
│  • Real URL Interception (chrome.webNavigation)        │
│  • Content In-Page Scanner (content.js)                │
│  • Quishing / QR Detector (qr_scanner.js)              │
│  • Email Deceptive Link Shield (gmail_content.js)      │
│  • Threat Interception Screen (warning.html)           │
└───────────────────────────┬────────────────────────────┘
                            │ REST / SSE Heartbeats & Events
                            ▼
┌────────────────────────────────────────────────────────┐
│             Central Enterprise Server                  │
│                    (Node.js / Express)                 │
│                                                        │
│  • Client Enrollment & Registration (/api/clients)     │
│  • Central Security Decision Engine (/api/security)    │
│  • Deterministic Rules CRUD Engine (/api/rules)        │
│  • Real-Time Alert & Incident Generator (/api/alerts)  │
│  • Real-time SSE Broadcast Hub (/api/dashboard)        │
│  • Admin Auth & Audit Trails (/api/auth, /audit-logs)  │
└───────────────────────────┬────────────────────────────┘
                            │ Direct SQL Transactions
                            ▼
┌────────────────────────────────────────────────────────┐
│               Persistent SQLite Database               │
│                    (phishguard.db)                     │
│                                                        │
│  • clients          • rules         • url_events       │
│  • alerts           • incidents     • audit_logs       │
│  • users            • system_config                    │
└────────────────────────────────────────────────────────┘
```

---

## 2. Chrome Extension Installation Guide

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left corner.
4. Select the PhishGuard project root directory.
5. Click the PhishGuard puzzle/shield icon in the browser toolbar.
6. Verify your generated **Client ID** (e.g., `CLIENT-7KX8A2`) and confirm connection to the Central Server URL.

---

## 3. Core Enterprise Features

### A. Centralized Client Fleet Management
- **Automatic Enrollment**: Extension instances generate a unique persistent client identifier on first run and enroll with the central database.
- **Real-Time Heartbeats**: Periodic background signals report online/offline status. Systems idle longer than the configured timeout automatically transition to `OFFLINE`.
- **System Telemetry**: Tracks hostname, OS, browser version, extension build, IP address, and total inspected navigations.

### B. Real-Time URL Monitoring & Interception
- Top-level frame navigations trigger an evaluation against the central policy rules and threat heuristics.
- If a site is determined to be a **BLOCK** target, the extension halts navigation and redirects the active tab to `warning.html`.
- If a site is flagged with a **WARNING**, warnings are logged, badges update, and alerts are dispatched to the SOC console.

### C. Deterministic Administrative Rules Engine
- Rules support `ALLOW`, `WARNING`, and `BLOCK` outcomes.
- Match types include exact domain, full URL, or glob/wildcard patterns (`*.xyz`).
- Strict priority evaluation ensures explicit organizational whitelists or high-priority blocks supersede lower-ranked heuristics.

### D. Incident Management & Security Alerts
- Threat navigations generate actionable alerts (`NEW`, `ACKNOWLEDGED`, `RESOLVED`).
- Correlated events group under active client incidents for security review.

### E. Real-Time Security Operations Dashboard
- Live Server-Sent Events (SSE) feed streams real navigation events across the entire fleet.
- Searchable URL history with multi-parameter filtering and CSV data export.
- Full administrative audit trail tracking rule modifications, client changes, and logins.

---

## 4. Configuration & Environment Variables

Create or update your `.env` file based on `.env.example`:

```env
SERVER_PORT=3000
DATABASE_URL=./phishguard.db
JWT_SECRET=your-secure-jwt-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=PhishGuardAdmin2026!
```

---

## 5. Verifying the System

- **Dashboard**: Visit `http://localhost:3000` to access the SOC management console.
- **Default Credentials**: Username `admin` / Password `PhishGuardAdmin2026!`.
- **API Health**: `GET /api/health` returns operational status and uptime.
- **Simulator**: Test sample URLs and client actions using the interactive Simulator tab in the dashboard.
