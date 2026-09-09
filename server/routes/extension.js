import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const archiver = require('archiver');

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, '..', '..');

// Required files comprising the full Chrome Extension
const EXTENSION_FILES = [
  'manifest.json',
  'background.js',
  'content.js',
  'engine.js',
  'popup.html',
  'popup.js',
  'warning.html',
  'warning.js',
  'gmail_content.js',
  'qr_scanner.js',
  'jsqr.min.js',
  'styles.css',
  'icon.png'
];

// 1. Get Extension Package Info & Files List
router.get('/info', (req, res) => {
  try {
    const manifestPath = path.join(ROOT_DIR, 'manifest.json');
    let manifestData = { version: '1.4', name: 'FortiNex' };
    if (fs.existsSync(manifestPath)) {
      manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    const filesInfo = EXTENSION_FILES.map((filename) => {
      const fullPath = path.join(ROOT_DIR, filename);
      const exists = fs.existsSync(fullPath);
      const size = exists ? fs.statSync(fullPath).size : 0;
      return { filename, exists, size };
    });

    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
    const detectedServerUrl = `${protocol}://${host}`;

    res.json({
      name: manifestData.name || 'FortiNex',
      version: manifestData.version || '1.4',
      manifestVersion: manifestData.manifest_version || 3,
      files: filesInfo,
      detectedServerUrl,
      downloadUrl: '/api/extension/download'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to inspect extension package: ' + err.message });
  }
});

// 2. Download Real Extension ZIP Package
router.get('/download', (req, res) => {
  try {
    // Determine target server URL for the extension
    const customServerUrl = req.query.serverUrl;
    let targetServerUrl = customServerUrl;

    if (!targetServerUrl) {
      const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      if (host && !host.includes('localhost') && !host.includes('127.0.0.1')) {
        targetServerUrl = `${protocol}://${host}`;
      } else {
        targetServerUrl = 'http://localhost:3000';
      }
    }

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="FortiNex-Extension.zip"');

    const archive = (typeof archiver === 'function')
      ? archiver('zip', { zlib: { level: 9 } })
      : new archiver.ZipArchive({ zlib: { level: 9 } });

    archive.on('error', (err) => {
      console.error('[Extension ZIP] Archiver error:', err);
      if (!res.headersSent) {
        res.status(500).send({ error: 'Archiving error: ' + err.message });
      }
    });

    archive.pipe(res);

    for (const filename of EXTENSION_FILES) {
      const fullPath = path.join(ROOT_DIR, filename);
      if (!fs.existsSync(fullPath)) {
        console.warn(`[Extension ZIP] Missing file skipped: ${filename}`);
        continue;
      }

      // If background.js, dynamically inject targetServerUrl so unpacked extension connects seamlessly
      if (filename === 'background.js') {
        let content = fs.readFileSync(fullPath, 'utf8');
        content = content.replace(
          /const DEFAULT_SERVER_URL\s*=\s*['"][^'"]+['"];/,
          `const DEFAULT_SERVER_URL = '${targetServerUrl}';`
        );
        // Include both in FortiNex-Extension folder and at root of archive for compatibility
        archive.append(content, { name: path.join('FortiNex-Extension', filename) });
      } else if (filename === 'manifest.json') {
        let manifestContent = fs.readFileSync(fullPath, 'utf8');
        try {
          const parsed = JSON.parse(manifestContent);
          parsed.name = 'FortiNex - Enterprise Browser Security';
          parsed.description = 'Enterprise-grade browser endpoint threat monitoring, URL interception, and SOC fleet security.';
          manifestContent = JSON.stringify(parsed, null, 2);
        } catch {
          // Keep as is
        }
        archive.append(manifestContent, { name: path.join('FortiNex-Extension', filename) });
      } else {
        archive.file(fullPath, { name: path.join('FortiNex-Extension', filename) });
      }
    }

    archive.finalize();
  } catch (err) {
    console.error('[Extension ZIP] Download failure:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Download failed: ' + err.message });
    }
  }
});

export default router;
