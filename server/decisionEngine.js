import { db } from './db.js';
import { evaluatePhishing, extractUrlFeatures } from '../engine.js';

/**
 * Match a pattern against a target string.
 * Supports:
 * - exact matches
 * - wildcard prefixes (*.example.com)
 * - wildcard infixes (*phish*)
 * - path wildcards (http://badsite.com/*)
 */
function matchesPattern(pattern, target, isDomainOnly = false) {
  if (!pattern || !target) return false;

  const p = pattern.trim().toLowerCase();
  const t = target.trim().toLowerCase();

  // Exact match
  if (p === t) return true;

  // Domain specific sub-domain match (e.g. pattern = example.com matches sub.example.com)
  if (isDomainOnly) {
    if (t.endsWith('.' + p)) return true;
  }

  // Wildcard pattern (e.g. *.example.com or *badsite*)
  if (p.includes('*')) {
    const escaped = p
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    try {
      const regex = new RegExp(`^${escaped}$`, 'i');
      if (regex.test(t)) return true;
    } catch {
      // invalid regex fallback
    }
  }

  return false;
}

/**
 * Evaluate URL security decision.
 * Returns:
 * {
 *   decision: 'ALLOW' | 'WARNING' | 'BLOCK',
 *   threatLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
 *   reason: string,
 *   ruleId: string | null,
 *   ruleName: string | null,
 *   features: object,
 *   heuristicScore: number
 * }
 */
export function evaluateUrlDecision(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      decision: 'ALLOW',
      threatLevel: 'SAFE',
      reason: 'Empty or invalid URL provided',
      ruleId: null,
      ruleName: null,
      features: {},
      heuristicScore: 0
    };
  }

  let parsedUrl;
  let domain = rawUrl;
  try {
    parsedUrl = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
    domain = parsedUrl.hostname.toLowerCase();
  } catch {
    domain = rawUrl.toLowerCase();
  }

  // 1. Fetch all active administrative rules ordered by priority DESC
  const rules = db.prepare(`
    SELECT * FROM rules
    WHERE enabled = 1
    ORDER BY priority DESC, created_at ASC
  `).all();

  // 2. Check rules in order of priority and specificity
  for (const rule of rules) {
    let matched = false;

    if (rule.target_type === 'domain') {
      matched = matchesPattern(rule.pattern, domain, true);
    } else if (rule.target_type === 'url') {
      matched = matchesPattern(rule.pattern, rawUrl, false);
    } else if (rule.target_type === 'wildcard') {
      matched = matchesPattern(rule.pattern, domain, true) || matchesPattern(rule.pattern, rawUrl, false);
    }

    if (matched) {
      let threatLevel = rule.severity || 'MEDIUM';
      if (rule.type === 'BLOCK' && (!threatLevel || threatLevel === 'LOW')) {
        threatLevel = 'HIGH';
      } else if (rule.type === 'ALLOW') {
        threatLevel = 'SAFE';
      }

      return {
        decision: rule.type, // 'ALLOW', 'WARNING', 'BLOCK'
        threatLevel,
        reason: rule.description || `Matched administrative ${rule.type} security rule (${rule.pattern})`,
        ruleId: rule.id,
        ruleName: rule.pattern,
        features: extractUrlFeatures(rawUrl),
        heuristicScore: rule.type === 'BLOCK' ? 100 : (rule.type === 'WARNING' ? 50 : 0)
      };
    }
  }

  // 3. If no administrative rule matched, run ML heuristic engine
  const heuristicResult = evaluatePhishing(rawUrl, []);
  let decision = 'ALLOW';
  let threatLevel = 'SAFE';

  if (heuristicResult.verdict === 'phishing') {
    decision = 'BLOCK';
    threatLevel = heuristicResult.score >= 85 ? 'CRITICAL' : 'HIGH';
  } else if (heuristicResult.verdict === 'suspicious') {
    decision = 'WARNING';
    threatLevel = 'MEDIUM';
  } else {
    decision = 'ALLOW';
    threatLevel = heuristicResult.score > 20 ? 'LOW' : 'SAFE';
  }

  const primaryReason = (heuristicResult.reasons && heuristicResult.reasons.length > 0)
    ? heuristicResult.reasons.join('; ')
    : 'No malicious indicators detected';

  return {
    decision,
    threatLevel,
    reason: primaryReason,
    ruleId: null,
    ruleName: heuristicResult.verdict === 'safe' ? 'ML Heuristic: Legitimate Domain' : 'ML Threat Detection Engine',
    features: heuristicResult.features || extractUrlFeatures(rawUrl),
    heuristicScore: heuristicResult.score || 0
  };
}
