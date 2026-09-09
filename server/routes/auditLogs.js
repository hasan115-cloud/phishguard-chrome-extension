import express from 'express';
import { db } from '../db.js';

const router = express.Router();

router.get('/', (req, res) => {
  const { limit = 100 } = req.query;
  const limitNum = Math.min(500, Math.max(1, parseInt(limit, 10) || 100));

  const logs = db.prepare(`
    SELECT * FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT ?
  `).all(limitNum);

  res.json({ logs });
});

export default router;
