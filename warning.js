// PhishGuard Enterprise Warning Screen Handler

(function () {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const rawUrl = params.get('url') || 'http://paypal-security-update.account-verify.xyz/signin';
  const score = params.get('score') || '95';
  const verdict = params.get('verdict') || 'phishing';
  const matchedRule = params.get('rule');
  const clientId = params.get('clientId');
  const allowBypass = params.get('allowBypass') === '1';

  let reasons = [];
  const singleReason = params.get('reason');
  const rawReasons = params.get('reasons');

  if (singleReason) {
    reasons = singleReason.split(';').map(s => s.trim()).filter(Boolean);
  } else if (rawReasons) {
    try {
      reasons = JSON.parse(rawReasons);
    } catch {
      reasons = rawReasons.split('|').filter(Boolean);
    }
  }

  if (reasons.length === 0) {
    if (verdict === 'suspicious') {
      reasons = [
        'Contains sensitive authentication keywords in URL path',
        'Uncommon domain pattern with elevated risk profile'
      ];
    } else {
      reasons = [
        'Matched administrative security block policy or malicious reputation list',
        'Credential harvesting pattern identified in navigation destination',
        'Deceptive domain structure detected'
      ];
    }
  }

  const blockedUrlEl = document.getElementById('blockedUrl');
  const scorePillEl = document.getElementById('scorePill');
  const rulePillEl = document.getElementById('rulePill');
  const clientPillEl = document.getElementById('clientPill');
  const timePillEl = document.getElementById('timePill');
  const reasonsBlockEl = document.getElementById('reasonsBlock');
  const reasonsListEl = document.getElementById('reasonsList');
  const btnBackEl = document.getElementById('btnBack');
  const btnProceedEl = document.getElementById('btnProceed');
  const policyLockEl = document.getElementById('policyLock');

  if (blockedUrlEl) blockedUrlEl.textContent = rawUrl;

  const scoreNum = parseInt(score, 10) || 90;
  let threatLevelText = 'Threat Level: HIGH';
  if (scoreNum >= 90) threatLevelText = 'Threat Level: CRITICAL';
  else if (scoreNum >= 40) threatLevelText = 'Threat Level: MEDIUM';
  else threatLevelText = 'Threat Level: LOW';

  if (scorePillEl) scorePillEl.textContent = `${threatLevelText} (${scoreNum}/100)`;

  if (rulePillEl && matchedRule) {
    rulePillEl.textContent = `Rule: ${matchedRule}`;
    rulePillEl.style.display = 'inline-block';
  }

  if (clientPillEl && clientId) {
    clientPillEl.textContent = `System: ${clientId}`;
    clientPillEl.style.display = 'inline-block';
  }

  if (timePillEl) {
    timePillEl.textContent = `Blocked: ${new Date().toLocaleTimeString()}`;
  }

  if (verdict === 'suspicious') {
    document.body.classList.add('suspicious');
    document.title = 'PhishGuard — Suspicious Site Warning';
    const h1 = document.getElementById('warningHeading');
    if (h1) h1.textContent = 'Suspicious Site Flagged';
    const icon = document.getElementById('warningIcon');
    if (icon) icon.textContent = '⚠️';
    const subtitle = document.getElementById('warningSubtitle');
    if (subtitle) {
      subtitle.textContent = 'PhishGuard has flagged this website as potentially suspicious. Proceed with extreme caution.';
    }
  }

  if (reasonsListEl && reasons.length > 0) {
    reasonsBlockEl.style.display = 'block';
    reasonsListEl.innerHTML = '';
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsListEl.appendChild(li);
    });
  }

  // Bypass policy enforcement
  if (allowBypass && btnProceedEl) {
    btnProceedEl.style.display = 'inline-block';
    btnProceedEl.addEventListener('click', () => {
      const confirmed = window.confirm(
        'SECURITY WARNING: You are proceeding to a high-risk website. Do not enter passwords or credentials.\n\nProceed anyway?'
      );
      if (confirmed) {
        window.location.href = rawUrl;
      }
    });
  } else {
    if (btnProceedEl) btnProceedEl.style.display = 'none';
    if (policyLockEl) policyLockEl.style.display = 'block';
  }

  if (btnBackEl) {
    btnBackEl.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'about:blank';
      }
    });
  }
})();
