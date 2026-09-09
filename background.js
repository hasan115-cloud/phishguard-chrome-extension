// PhishGuard Enterprise Background Service Worker (Manifest V3)
// Real URL monitoring, Central Server enrollment, Heartbeat, and Interceptive Blocking

const DEFAULT_SERVER_URL = 'http://localhost:3000';
const DEFAULT_TRUSTED = [
  'google.com', 'accounts.google.com', 'microsoft.com', 'apple.com',
  'amazon.com', 'github.com', 'paypal.com', 'chase.com'
];

let cachedServerUrl = DEFAULT_SERVER_URL;
let cachedClientId = null;
let cachedSystemName = null;
let offlineEventQueue = [];

// Helper: Generate persistent Unique Client ID
function generateClientId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let rand = '';
  for (let i = 0; i < 6; i++) {
    rand += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `CLIENT-${rand}`;
}

// Initialize Client Configuration and Enrollment
async function initializeClient() {
  chrome.storage.local.get(
    ['clientId', 'systemName', 'serverUrl', 'enrollmentToken', 'trustedDomains', 'soundEnabled', 'offlineQueue'],
    async (data) => {
      // 1. Client ID
      if (!data.clientId) {
        cachedClientId = generateClientId();
        chrome.storage.local.set({ clientId: cachedClientId });
      } else {
        cachedClientId = data.clientId;
      }

      // 2. Server URL
      cachedServerUrl = data.serverUrl || DEFAULT_SERVER_URL;

      // 3. System Name
      cachedSystemName = data.systemName || cachedClientId;

      // 4. Default Trusted & Sound
      if (!data.trustedDomains) {
        chrome.storage.local.set({ trustedDomains: DEFAULT_TRUSTED });
      }
      if (data.soundEnabled === undefined) {
        chrome.storage.local.set({ soundEnabled: true });
      }
      if (data.offlineQueue) {
        offlineEventQueue = data.offlineQueue;
      }

      console.log(`[FortiNex] Initialized ${cachedClientId} -> Server: ${cachedServerUrl}`);

      // Perform Central Server Enrollment
      await registerWithServer();

      // Flush any queued offline events
      flushOfflineQueue();
    }
  );
}

// Enroll / Register with Central Server
async function registerWithServer() {
  try {
    let osName = 'Desktop';
    if (chrome.runtime.getPlatformInfo) {
      const info = await new Promise((resolve) => chrome.runtime.getPlatformInfo(resolve));
      osName = `${info.os} (${info.arch})`;
    }

    const storageData = await new Promise((resolve) =>
      chrome.storage.local.get(['serverUrl', 'enrollmentToken', 'systemName'], resolve)
    );
    if (storageData.serverUrl) cachedServerUrl = storageData.serverUrl;
    if (storageData.systemName) cachedSystemName = storageData.systemName;

    const manifest = chrome.runtime.getManifest();
    const payload = {
      clientId: cachedClientId,
      systemName: cachedSystemName,
      hostname: `${osName.toLowerCase().replace(/[^a-z0-9]/g, '-')}-workstation`,
      os: osName,
      browser: `Chrome ${navigator.userAgent.match(/Chrome\/([0-9.]+)/)?.[1] || 'V3'}`,
      extensionVersion: manifest.version,
      enrollmentToken: storageData.enrollmentToken || undefined,
      metadata: {
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        installedAt: new Date().toISOString()
      }
    };

    const res = await fetch(`${cachedServerUrl}/api/clients/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      const data = await res.json();
      console.log('[FortiNex] Registered with Central Server:', data);
      chrome.storage.local.set({ serverConnected: true, lastRegisterTime: Date.now() });
    } else {
      console.warn('[FortiNex] Server registration returned status:', res.status);
    }
  } catch (err) {
    console.warn('[FortiNex] Central server registration deferred (offline or unreachable):', err.message);
    chrome.storage.local.set({ serverConnected: false });
  }
}

// Listen for dynamic storage updates (e.g. user changes Server URL or Token in popup)
if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
      let shouldReRegister = false;
      if (changes.serverUrl) {
        cachedServerUrl = changes.serverUrl.newValue || DEFAULT_SERVER_URL;
        shouldReRegister = true;
      }
      if (changes.systemName) {
        cachedSystemName = changes.systemName.newValue;
        shouldReRegister = true;
      }
      if (changes.enrollmentToken) {
        shouldReRegister = true;
      }
      if (shouldReRegister) {
        registerWithServer();
      }
    }
  });
}

// Periodic Heartbeat to Central Server
async function sendHeartbeat() {
  if (!cachedClientId) return;

  try {
    const res = await fetch(`${cachedServerUrl}/api/clients/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: cachedClientId })
    });

    if (res.ok) {
      chrome.storage.local.set({ serverConnected: true, lastHeartbeatTime: Date.now() });
    }
  } catch (err) {
    chrome.storage.local.set({ serverConnected: false });
    console.debug('[PhishGuard] Heartbeat failed, server unreachable.');
  }
}

// Flush Offline Queued Events
async function flushOfflineQueue() {
  if (offlineEventQueue.length === 0) return;

  const queueCopy = [...offlineEventQueue];
  offlineEventQueue = [];
  chrome.storage.local.set({ offlineQueue: [] });

  for (const item of queueCopy) {
    try {
      await fetch(`${cachedServerUrl}/api/url-events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(item)
      });
    } catch {
      // Re-queue if still failed
      offlineEventQueue.push(item);
    }
  }

  if (offlineEventQueue.length > 0) {
    chrome.storage.local.set({ offlineQueue: offlineEventQueue });
  }
}

// Fallback Heuristic Phishing Evaluator (Preserved from existing extension)
function evaluateUrlLocal(rawUrl, trustedList = []) {
  try {
    const u = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
    const host = u.hostname.toLowerCase();
    const pathname = u.pathname.toLowerCase();
    const search = u.search.toLowerCase();

    if (trustedList.some(d => host === d || host.endsWith('.' + d))) {
      return { url: rawUrl, domain: host, verdict: 'safe', score: 0, reasons: ['Whitelisted domain'] };
    }

    let score = 5;
    const reasons = [];

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      score += 50;
      reasons.push('Numerical IP address used as hostname');
    }

    if (rawUrl.includes('@')) {
      score += 40;
      reasons.push('URL contains deceptive "@" redirection');
    }

    const tld = host.split('.').pop();
    const highRiskTlds = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'club', 'work'];
    if (highRiskTlds.includes(tld)) {
      score += 30;
      reasons.push(`High-risk top-level domain (.${tld})`);
    }

    const brands = ['paypal', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'chase', 'binance'];
    for (const b of brands) {
      if (host.includes(b) && !host.endsWith(`.${b}.com`) && host !== `${b}.com`) {
        score += 45;
        reasons.push(`Brand impersonation of ${b}`);
        break;
      }
    }

    const keywords = ['login', 'signin', 'verify', 'account', 'security', 'banking', 'wallet'];
    const matched = keywords.filter(k => host.includes(k) || pathname.includes(k) || search.includes(k));
    if (matched.length > 0) {
      score += matched.length * 12;
      reasons.push(`Sensitive authentication keywords detected (${matched.join(', ')})`);
    }

    const subCount = host.split('.').length - 2;
    if (subCount >= 3) {
      score += 20;
      reasons.push(`Excessive subdomain hierarchy (${subCount} levels)`);
    }

    score = Math.min(score, 99);
    const verdict = score >= 70 ? 'phishing' : score >= 35 ? 'suspicious' : 'safe';
    if (reasons.length === 0) reasons.push('Legitimate domain structure verified');

    return { url: rawUrl, domain: host, verdict, score, reasons };
  } catch {
    return { url: rawUrl, domain: 'unknown', verdict: 'safe', score: 0, reasons: ['Invalid or non-web URL'] };
  }
}

// -------------------------------------------------------------
// REAL URL MONITORING & INTERCEPTIVE BLOCKING
// Manifest V3 Navigation Interception via chrome.webNavigation
// -------------------------------------------------------------
async function handleUrlNavigation(tabId, rawUrl) {
  if (!rawUrl || !rawUrl.startsWith('http')) return;

  // Ignore internal/extension traffic
  if (rawUrl.includes('warning.html') || rawUrl.includes(cachedServerUrl)) return;

  try {
    // 1. Query Central Security Decision Engine
    let decisionResult = null;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500); // 2.5s fast timeout

      const res = await fetch(`${cachedServerUrl}/api/security/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: rawUrl,
          clientId: cachedClientId,
          systemName: cachedSystemName,
          tabId
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        decisionResult = await res.json();
      }
    } catch (netErr) {
      console.debug('[PhishGuard] Central server check timed out or offline, evaluating locally:', netErr.message);
    }

    // 2. Fallback to local heuristic if server was unreachable
    if (!decisionResult) {
      const local = evaluateUrlLocal(rawUrl, DEFAULT_TRUSTED);
      decisionResult = {
        decision: local.verdict === 'phishing' ? 'BLOCK' : (local.verdict === 'suspicious' ? 'WARNING' : 'ALLOW'),
        threatLevel: local.verdict === 'phishing' ? 'HIGH' : (local.verdict === 'suspicious' ? 'MEDIUM' : 'SAFE'),
        reason: local.reasons.join('; '),
        ruleName: 'Local Heuristic Fallback',
        heuristicScore: local.score,
        url: rawUrl,
        domain: local.domain
      };

      // Queue event to report when server reconnects
      offlineEventQueue.push({
        url: rawUrl,
        clientId: cachedClientId,
        systemName: cachedSystemName,
        decision: decisionResult.decision,
        threatLevel: decisionResult.threatLevel,
        reason: decisionResult.reason
      });
      chrome.storage.local.set({ offlineQueue: offlineEventQueue });
    }

    // 3. ACTUALLY BLOCK AND INTERRUPT NAVIGATION IF DECISION IS BLOCK
    if (decisionResult.decision === 'BLOCK') {
      console.warn(`[PhishGuard] 🛑 BLOCKING NAVIGATION: ${rawUrl} (Reason: ${decisionResult.reason})`);

      const warningUrl = chrome.runtime.getURL(
        `warning.html?url=${encodeURIComponent(rawUrl)}&domain=${encodeURIComponent(decisionResult.domain || '')}&verdict=phishing&score=${decisionResult.heuristicScore || 95}&reason=${encodeURIComponent(decisionResult.reason || '')}&rule=${encodeURIComponent(decisionResult.ruleName || '')}&clientId=${encodeURIComponent(cachedClientId || '')}&allowBypass=0`
      );

      chrome.tabs.update(tabId, { url: warningUrl });

      // Update badge
      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#dc3545', tabId });
      }
    } else if (decisionResult.decision === 'WARNING') {
      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '?', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
      }
    } else {
      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '', tabId });
      }
    }
  } catch (err) {
    console.error('[PhishGuard] Navigation handler error:', err);
  }
}

// Listen to webNavigation (primary Manifest V3 navigation interceptor)
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only intercept top-level frame navigation
    if (details.frameId === 0) {
      handleUrlNavigation(details.tabId, details.url);
    }
  });
}

// Fallback tab update listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
    // Already handled by webNavigation if supported, or backup here
    if (!chrome.webNavigation) {
      handleUrlNavigation(tabId, tab.url);
    }
  }
});

// Alarms for periodic heartbeat and queue flushing
chrome.alarms.create('phishguard-heartbeat', { periodInMinutes: 0.5 }); // every 30 seconds
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'phishguard-heartbeat') {
    sendHeartbeat();
    flushOfflineQueue();
  }
});

// Fallback interval in case alarms are delayed
setInterval(() => {
  sendHeartbeat();
}, 30000);

// Setup on extension install and browser startup
chrome.runtime.onInstalled.addListener(() => {
  initializeClient();
});

chrome.runtime.onStartup.addListener(() => {
  initializeClient();
});

// Initialize right away
initializeClient();

// Tab statistics map
const tabStatsMap = new Map();

// Message dispatching for popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CHECK_URL') {
    // First try Central Server API, fallback to local heuristic
    fetch(`${cachedServerUrl}/api/security/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: request.url,
        clientId: cachedClientId,
        systemName: cachedSystemName
      })
    })
      .then(r => r.json())
      .then(data => sendResponse(data))
      .catch(() => {
        chrome.storage.local.get(['trustedDomains'], (st) => {
          const res = evaluateUrlLocal(request.url, st.trustedDomains || DEFAULT_TRUSTED);
          sendResponse(res);
        });
      });
    return true;
  }

  if (request.action === 'GET_CLIENT_INFO') {
    sendResponse({
      clientId: cachedClientId,
      systemName: cachedSystemName,
      serverUrl: cachedServerUrl
    });
    return true;
  }

  if (request.action === 'SET_SERVER_URL') {
    if (request.serverUrl) {
      cachedServerUrl = request.serverUrl.replace(/\/+$/, '');
      chrome.storage.local.set({ serverUrl: cachedServerUrl }, () => {
        registerWithServer();
        sendResponse({ success: true, serverUrl: cachedServerUrl });
      });
      return true;
    }
  }

  if (request.action === 'UPDATE_TAB_STATS') {
    if (sender.tab && sender.tab.id) {
      tabStatsMap.set(sender.tab.id, request.stats);
    }
    sendResponse({ ok: true });
    return true;
  }

  if (request.action === 'GET_TAB_STATS') {
    const stats = tabStatsMap.get(request.tabId) || { total: 0, phishing: 0, suspicious: 0, safe: 0 };
    sendResponse(stats);
    return true;
  }
});
