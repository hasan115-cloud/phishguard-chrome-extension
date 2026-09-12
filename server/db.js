import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_PATH = process.env.DATABASE_URL || path.join(__dirname, '..', 'phishguard.db');

export const db = new DatabaseSync(DB_PATH);

export function getDatabase() {
  return db;
}

// Enable WAL mode and foreign keys for high performance and durability
try {
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
} catch (e) {
  console.debug('Pragma initialization note:', e.message);
}

// Initialize tables
export function initDatabase() {
  db.exec(`
    -- Users / Administrators
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      created_at TEXT NOT NULL,
      last_login TEXT
    );

    -- Registered Chrome Extension Clients / Systems
    CREATE TABLE IF NOT EXISTS clients (
      client_id TEXT PRIMARY KEY,
      system_name TEXT NOT NULL,
      hostname TEXT,
      os TEXT,
      browser TEXT,
      extension_version TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ONLINE',
      ip_address TEXT,
      client_metadata TEXT
    );

    -- URL Events Monitored
    CREATE TABLE IF NOT EXISTS url_events (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      system_name TEXT,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      decision TEXT NOT NULL, -- 'ALLOW', 'WARNING', 'BLOCK'
      threat_level TEXT NOT NULL, -- 'SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
      rule_id TEXT,
      rule_name TEXT,
      reason TEXT,
      browser_info TEXT,
      FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
    );

    -- Security Rules (ALLOW / WARNING / BLOCK)
    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL, -- 'ALLOW', 'WARNING', 'BLOCK'
      pattern TEXT NOT NULL, -- e.g. 'paypal-security.xyz', '*.badsite.com', 'http://192.168.1.105/*'
      target_type TEXT NOT NULL DEFAULT 'domain', -- 'domain', 'url', 'wildcard'
      description TEXT,
      severity TEXT NOT NULL DEFAULT 'MEDIUM', -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
      enabled INTEGER NOT NULL DEFAULT 1,
      priority INTEGER NOT NULL DEFAULT 10,
      created_by TEXT NOT NULL DEFAULT 'admin',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    -- Security Alerts
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      system_name TEXT,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      severity TEXT NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
      alert_type TEXT NOT NULL, -- 'PHISHING_BLOCKED', 'SUSPICIOUS_WARNING', 'MALICIOUS_DOMAIN', 'RULE_VIOLATION'
      reason TEXT NOT NULL,
      rule_id TEXT,
      status TEXT NOT NULL DEFAULT 'NEW', -- 'NEW', 'ACKNOWLEDGED', 'RESOLVED'
      resolved_at TEXT,
      resolved_by TEXT,
      FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
    );

    -- Security Incidents
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      client_id TEXT NOT NULL,
      system_name TEXT,
      start_time TEXT NOT NULL,
      last_activity TEXT NOT NULL,
      related_alert_count INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'
      notes TEXT,
      FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
    );

    -- Audit Logs
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      admin_user TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      result TEXT NOT NULL DEFAULT 'SUCCESS',
      ip_address TEXT,
      details TEXT
    );

    -- Enrollment Tokens for Extension Onboarding
    CREATE TABLE IF NOT EXISTS enrollment_tokens (
      token TEXT PRIMARY KEY,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'REVOKED', 'USED'
      max_uses INTEGER NOT NULL DEFAULT 25,
      uses_count INTEGER NOT NULL DEFAULT 0,
      description TEXT
    );

    -- System Configuration Key-Value Store
    CREATE TABLE IF NOT EXISTS system_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    -- Indices for performance
    CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_status ON enrollment_tokens(status);
    CREATE INDEX IF NOT EXISTS idx_url_events_client ON url_events(client_id);
    CREATE INDEX IF NOT EXISTS idx_url_events_timestamp ON url_events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_url_events_domain ON url_events(domain);
    CREATE INDEX IF NOT EXISTS idx_url_events_decision ON url_events(decision);
    CREATE INDEX IF NOT EXISTS idx_alerts_client ON alerts(client_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled, priority DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
  `);

  // Create default admin user and env user
  const usersToSeed = [
    { username: 'admin', password: 'PhishGuardAdmin2026!' },
    { username: process.env.ADMIN_USERNAME || 'hasan', password: process.env.ADMIN_PASSWORD || '@2026#Admin!92' }
  ];

  for (const u of usersToSeed) {
    if (!u.username) continue;
    const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(u.username);
    if (!existingUser) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(u.password, salt);
      const now = new Date().toISOString();
      db.prepare(`
        INSERT OR REPLACE INTO users (id, username, password_hash, role, created_at)
        VALUES (?, ?, ?, 'admin', ?)
      `).run('user-' + u.username, u.username, hash, now);
      console.log(`[DB] Administrator user initialized: ${u.username}`);
    }
  }

  // Seed default baseline enterprise security rules if table is empty
  const ruleCount = db.prepare('SELECT COUNT(*) as count FROM rules').get().count;
  if (ruleCount === 0) {
    const now = new Date().toISOString();
    const defaultRules = [
      {
        id: 'rule-blk-01',
        type: 'BLOCK',
        pattern: '*.account-verify.xyz',
        target_type: 'wildcard',
        description: 'Block known credential-phishing subdomains on .xyz TLD',
        severity: 'HIGH',
        priority: 100
      },
      {
        id: 'rule-blk-02',
        type: 'BLOCK',
        pattern: 'paypal-security-update.account-verify.xyz',
        target_type: 'domain',
        description: 'Block verified PayPal impersonation phishing domain',
        severity: 'CRITICAL',
        priority: 110
      },
      {
        id: 'rule-blk-03',
        type: 'BLOCK',
        pattern: 'apple-id-support-cloud.live-auth.top',
        target_type: 'domain',
        description: 'Block Apple ID typosquatting credential harvester',
        severity: 'CRITICAL',
        priority: 110
      },
      {
        id: 'rule-blk-04',
        type: 'BLOCK',
        pattern: '192.168.1.105',
        target_type: 'domain',
        description: 'Block raw numerical IP address banking masquerade',
        severity: 'HIGH',
        priority: 90
      },
      {
        id: 'rule-warn-01',
        type: 'WARNING',
        pattern: '*.club',
        target_type: 'wildcard',
        description: 'Warn users navigating to high-abuse .club domain registries',
        severity: 'MEDIUM',
        priority: 50
      },
      {
        id: 'rule-warn-02',
        type: 'WARNING',
        pattern: 'free-crypto-giveaway-airdrop.club',
        target_type: 'domain',
        description: 'Warn users on cryptocurrency giveaway landing pages',
        severity: 'MEDIUM',
        priority: 60
      },
      {
        id: 'rule-alw-01',
        type: 'ALLOW',
        pattern: 'github.com',
        target_type: 'domain',
        description: 'Enterprise trusted software development portal',
        severity: 'LOW',
        priority: 200
      },
      {
        id: 'rule-alw-02',
        type: 'ALLOW',
        pattern: '*.google.com',
        target_type: 'wildcard',
        description: 'Corporate Google Workspace services',
        severity: 'LOW',
        priority: 200
      },
      {
        id: 'rule-alw-03',
        type: 'ALLOW',
        pattern: '*.microsoft.com',
        target_type: 'wildcard',
        description: 'Microsoft 365 and Azure enterprise portals',
        severity: 'LOW',
        priority: 200
      }
    ];

    const insertRule = db.prepare(`
      INSERT INTO rules (id, type, pattern, target_type, description, severity, enabled, priority, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'system-init', ?, ?)
    `);

    for (const r of defaultRules) {
      insertRule.run(r.id, r.type, r.pattern, r.target_type, r.description, r.severity, r.priority, now, now);
    }
    console.log(`[DB] Baseline enterprise security policy rules installed (${defaultRules.length} rules)`);
  }

  // Set default system configuration if missing
  const initConfig = (key, value) => {
    const existing = db.prepare('SELECT key FROM system_config WHERE key = ?').get(key);
    if (!existing) {
      db.prepare('INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?)')
        .run(key, value, new Date().toISOString());
    }
  };

  initConfig('HEARTBEAT_TIMEOUT_SECONDS', '90');
  initConfig('ALLOW_USER_BYPASS', 'false');
  initConfig('AUTO_CREATE_INCIDENTS', 'true');
  initConfig('ENROLLMENT_TOKEN', 'ENROLL-FORTINEX-2026');

  // Seed default enrollment token
  const existingToken = db.prepare('SELECT token FROM enrollment_tokens WHERE token = ?').get('ENROLL-FORTINEX-2026');
  if (!existingToken) {
    const now = new Date();
    const expires = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000); // 90 days validity
    db.prepare(`
      INSERT INTO enrollment_tokens (token, created_by, created_at, expires_at, status, max_uses, uses_count, description)
      VALUES (?, 'system-init', ?, ?, 'ACTIVE', 100, 0, 'Default PhishGuard Enterprise fleet enrollment token')
    `).run('ENROLL-FORTINEX-2026', now.toISOString(), expires.toISOString());
  }

  console.log('[DB] Persistent SQLite database ready at', DB_PATH);
}
