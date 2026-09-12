import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDatabase, db } from './server/db.js';
import { broadcast } from './server/sse.js';
import { evaluatePhishing, extractUrlFeatures, TRUSTED_DEFAULT_DOMAINS } from './engine.js';
import { evaluateUrlDecision } from './server/decisionEngine.js';

import authRoutes from './server/routes/auth.js';
import clientsRoutes from './server/routes/clients.js';
import securityRoutes from './server/routes/security.js';
import rulesRoutes from './server/routes/rules.js';
import alertsRoutes from './server/routes/alerts.js';
import dashboardRoutes from './server/routes/dashboard.js';
import reportsRoutes from './server/routes/reports.js';
import extensionRoutes from './server/routes/extension.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import os from 'os';

// Initialize persistent SQLite database
initDatabase();

const app = express();
const PORT = process.env.SERVER_PORT || 3000;

// Security & Robust CORS Middleware supporting chrome-extension://, LAN, and Remote HTTPS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Client-ID, X-System-Name, X-Enrollment-Token, X-Extension-Version, X-Requested-With, Accept, Origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logger for diagnostic tracing
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') && req.path !== '/api/clients/heartbeat' && req.path !== '/api/dashboard/events-stream') {
    console.log(`[HTTP] ${req.method} ${req.path}`);
  }
  next();
});

// Helper: detect local LAN IP
function getDetectedLanIp() {
  try {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('169.254')) {
          return iface.address;
        }
      }
    }
  } catch {}
  return '127.0.0.1';
}

// Health & Ping endpoints
app.get(['/api/health', '/api/ping', '/api/security/ping'], (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    service: 'PhishGuard Central Enterprise Platform'
  });
});

// Dynamic Multi-Mode Connectivity Config endpoint for Chrome Extension
app.get(['/api/config', '/api/extension/config'], (req, res) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
  const isRemote = host && !host.includes('localhost') && !host.includes('127.0.0.1');
  const detectedRemoteUrl = isRemote
    ? `${protocol}://${host}`
    : 'https://ais-dev-edwrwsrecrzqlafgs46yj5-361661540763.asia-southeast1.run.app';
  
  const lanIp = getDetectedLanIp();
  const lanUrl = lanIp !== '127.0.0.1' ? `http://${lanIp}:${PORT}` : `http://localhost:${PORT}`;
  const localhostUrl = `http://localhost:${PORT}`;

  const activeTokenRow = db.prepare("SELECT token FROM enrollment_tokens WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1").get();
  const activeToken = activeTokenRow ? activeTokenRow.token : 'ENROLL-PHISHGUARD-2026';

  res.json({
    modes: {
      localhost: localhostUrl,
      lan: lanUrl,
      remote: detectedRemoteUrl
    },
    currentDetectedMode: isRemote ? 'remote' : 'localhost',
    recommendedServerUrl: isRemote ? detectedRemoteUrl : localhostUrl,
    activeEnrollmentToken: activeToken,
    version: '1.4',
    service: 'PhishGuard Central Enterprise Platform'
  });
});

// Core Enterprise API Routes
app.use('/api/auth', authRoutes);
app.use('/api/clients', clientsRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/url-events', securityRoutes);
app.use('/api/events', securityRoutes);
app.use('/api/extension', extensionRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/alerts', alertsRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/reports', reportsRoutes);

// Vendor assets (jsPDF & jsPDF-autotable)
app.use('/vendor', express.static(path.join(__dirname, 'node_modules')));

// Backwards-compatible endpoints for extension popup / existing client calls
const trustedDomains = new Set([...TRUSTED_DEFAULT_DOMAINS]);

app.post('/api/scan', (req, res) => {
  const { url, trusted, clientId, systemName } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  // Forward to central security check-url logic
  const now = new Date().toISOString();
  const activeClientId = clientId || 'CLIENT-WEB-SCANNER';
  const assignedName = systemName || 'Web Scanner';

  let clientRecord = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(activeClientId);
  if (!clientRecord) {
    db.prepare(`
      INSERT INTO clients (
        client_id, system_name, hostname, os, browser,
        extension_version, first_seen, last_seen, status, ip_address, client_metadata
      ) VALUES (?, ?, 'web-host', 'Web Interface', 'Google Chrome', '1.4', ?, ?, 'ONLINE', '127.0.0.1', '{}')
    `).run(activeClientId, assignedName, now, now);
  }

  const combinedTrusted = Array.from(trustedDomains);
  if (Array.isArray(trusted)) {
    trusted.forEach(d => combinedTrusted.push(d));
  }

  const evalResult = evaluateUrlDecision(url);
  const finalVerdict = evalResult.decision === 'BLOCK' ? 'phishing' : (evalResult.decision === 'WARNING' ? 'suspicious' : 'safe');
  const decision = evalResult.decision;
  const threatLevel = evalResult.threatLevel;

  // Insert URL event
  const eventId = 'ev-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
  let domain = url;
  try {
    domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
  } catch {
    domain = url;
  }

  db.prepare(`
    INSERT INTO url_events (
      id, client_id, system_name, url, domain, timestamp,
      decision, threat_level, rule_id, rule_name, reason, browser_info
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')
  `).run(
    eventId,
    activeClientId,
    assignedName,
    url,
    domain,
    now,
    decision,
    threatLevel,
    evalResult.ruleId,
    evalResult.ruleName,
    evalResult.reason
  );

  broadcast('URL_EVENT', {
    id: eventId,
    clientId: activeClientId,
    systemName: assignedName,
    url,
    domain,
    timestamp: now,
    decision,
    threatLevel,
    reason: evalResult.reason
  });

  res.json({
    url,
    domain,
    verdict: finalVerdict,
    score: evalResult.features?.heuristicScore || (finalVerdict === 'phishing' ? 95 : 5),
    reasons: [evalResult.reason],
    features: evalResult.features || {},
    decision,
    threatLevel
  });
});

app.post('/api/batch-scan', (req, res) => {
  const { urls } = req.body;
  if (!Array.isArray(urls)) {
    return res.status(400).json({ error: 'urls array is required' });
  }
  const combinedTrusted = Array.from(trustedDomains);
  const results = urls.map(u => evaluatePhishing(u, combinedTrusted));
  res.json({ count: results.length, results });
});

app.post('/api/analyze-features', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  const features = extractUrlFeatures(url);
  res.json(features);
});

app.get('/api/stats', (req, res) => {
  const urlStats = db.prepare(`
    SELECT
      COUNT(*) as total_scanned,
      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as phishing_blocked,
      SUM(CASE WHEN decision = 'WARNING' THEN 1 ELSE 0 END) as suspicious_flagged,
      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as safe_verified
    FROM url_events
  `).get();

  const clientCount = db.prepare('SELECT COUNT(*) as count FROM clients').get().count;

  res.json({
    totalScanned: urlStats.total_scanned || 0,
    phishingBlocked: urlStats.phishing_blocked || 0,
    suspiciousFlagged: urlStats.suspicious_flagged || 0,
    safeVerified: urlStats.safe_verified || 0,
    totalClients: clientCount,
    trustedCount: trustedDomains.size
  });
});

app.get('/api/trusted', (req, res) => {
  res.json({ trusted: Array.from(trustedDomains) });
});

app.post('/api/trust', (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });
  trustedDomains.add(domain.toLowerCase().trim());
  res.json({ success: true, trusted: Array.from(trustedDomains) });
});

app.delete('/api/trust/:domain', (req, res) => {
  const domain = req.params.domain.toLowerCase().trim();
  trustedDomains.delete(domain);
  res.json({ success: true, trusted: Array.from(trustedDomains) });
});

app.get('/api/recent', (req, res) => {
  const events = db.prepare(`
    SELECT url, domain,
           CASE WHEN decision = 'BLOCK' THEN 'phishing'
                WHEN decision = 'WARNING' THEN 'suspicious'
                ELSE 'safe' END as verdict,
           CASE WHEN decision = 'BLOCK' THEN 95
                WHEN decision = 'WARNING' THEN 50
                ELSE 5 END as score,
           reason as reasons,
           timestamp
    FROM url_events
    ORDER BY timestamp DESC
    LIMIT 20
  `).all();

  res.json({ recent: events });
});

// Periodic background task to transition inactive clients to OFFLINE
setInterval(() => {
  try {
    const timeoutRow = db.prepare("SELECT value FROM system_config WHERE key = 'HEARTBEAT_TIMEOUT_SECONDS'").get();
    const timeoutSec = timeoutRow ? parseInt(timeoutRow.value, 10) || 90 : 90;
    const thresholdDate = new Date(Date.now() - (timeoutSec * 1000)).toISOString();

    const result = db.prepare(`
      UPDATE clients
      SET status = 'OFFLINE'
      WHERE status = 'ONLINE' AND last_seen < ?
    `).run(thresholdDate);

    if (result.changes > 0) {
      broadcast('CLIENT_STATUS_REFRESH', { offlineCount: result.changes });
    }
  } catch (err) {
    console.debug('Heartbeat audit note:', err.message);
  }
}, 30000);

// Serve static extension and web application files
app.use(express.static(__dirname));

// Primary route: Enterprise Security Dashboard & Hub
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start listening on port 3000
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[PhishGuard] Central Enterprise Security Server listening on http://0.0.0.0:${PORT}`);
});
