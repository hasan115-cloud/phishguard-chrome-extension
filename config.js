// PhishGuard Extension - Central Configuration
// This file is auto-configured when downloading the extension ZIP from the central dashboard,
// and can also be adjusted dynamically via the Extension Options or Popup Settings UI.

const PHISHGUARD_CONFIG = {
  // Configurable Server URL (Dynamic / Auto-adaptive)
  // Supports Localhost (Dev), LAN (Internal Testing), and Remote (Cloud / Production)
  DEFAULT_SERVER_URL: 'http://localhost:3000',
  SERVER_MODE: 'AUTO', // 'AUTO' | 'LOCALHOST' | 'LAN' | 'REMOTE' | 'CUSTOM'

  // Pre-configured connection endpoints
  MODES: {
    LOCALHOST: 'http://localhost:3000',
    LAN: 'http://localhost:3000',
    REMOTE: 'https://ais-dev-vxn2qexqgxdrppk4vf2id5-361661540763.asia-southeast1.run.app'
  },

  // Fleet enrollment token
  DEFAULT_ENROLLMENT_TOKEN: 'ENROLL-PHISHGUARD-2026',

  // Extension metadata
  EXTENSION_NAME: 'PhishGuard Extension',
  VERSION: '1.4'
};

if (typeof globalThis !== 'undefined') {
  globalThis.PHISHGUARD_CONFIG = PHISHGUARD_CONFIG;
}

