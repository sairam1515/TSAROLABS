import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { z } from 'zod';

const app = express();
app.use(express.json({ limit: '200kb' }));
app.use(cors({ origin: true }));

const PORT = Number(process.env.PORT || 8787);

const IntelRequestSchema = z.object({
  firstName: z.string().trim().max(80).optional().default(''),
  lastName: z.string().trim().max(80).optional().default(''),
  keywords: z.string().trim().max(200).optional().default(''),
  identifiers: z
    .object({
      emails: z.array(z.string().trim().toLowerCase().max(254)).optional().default([]),
      usernames: z.array(z.string().trim().max(60)).optional().default([]),
      phones: z.array(z.string().trim().max(30)).optional().default([])
    })
    .optional()
    .default({ emails: [], usernames: [], phones: [] })
});

function nowIso() {
  return new Date().toISOString();
}

function buildSubjectName({ firstName, lastName }) {
  const name = [firstName, lastName].filter(Boolean).join(' ').trim();
  return name || 'Unknown';
}

function redactEmail(email) {
  const at = email.indexOf('@');
  if (at <= 1) return '[redacted-email]';
  const user = email.slice(0, at);
  const domain = email.slice(at + 1);
  return `${user[0]}***@${domain}`;
}

function computeRisk(matchesCount) {
  if (matchesCount >= 5) return { level: 'high', score: 85, rationale: 'Multiple breach exposures reported by licensed sources.' };
  if (matchesCount >= 1) return { level: 'medium', score: 55, rationale: 'At least one breach exposure reported by licensed sources.' };
  return { level: 'low', score: 15, rationale: 'No breach exposures found from configured sources.' };
}

function recommendedSources() {
  return [
    {
      name: 'Have I Been Pwned (HIBP)',
      type: 'breach_exposure',
      what_it_verifies: 'Whether a provided email appears in known breaches (metadata only).',
      how_to_enable: 'Set HIBP_API_KEY in backend environment.'
    },
    {
      name: 'GitHub (Code Search)',
      type: 'open_web',
      what_it_verifies: 'Public mentions of usernames/emails in code/issues (may indicate accidental exposure).',
      how_to_enable: 'Set GITHUB_TOKEN in backend environment (optional).'
    }
  ];
}

async function hibpBreachedAccount(email) {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) {
    return { enabled: false, email, matches: [], error: null };
  }

  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'hibp-api-key': apiKey,
      'user-agent': 'IndiaTrace/0.1 (local)',
      'accept': 'application/json'
    }
  });

  if (res.status === 404) {
    return { enabled: true, email, matches: [], error: null };
  }
  if (!res.ok) {
    let msg = `HIBP request failed (${res.status})`;
    try {
      const data = await res.json();
      if (data?.message) msg = data.message;
    } catch {}
    return { enabled: true, email, matches: [], error: msg };
  }

  const breaches = await res.json();
  const matches = Array.isArray(breaches)
    ? breaches.map(b => ({
        source: 'HIBP',
        type: 'breach_exposure',
        identifier_matched: { type: 'email', value_redacted: redactEmail(email) },
        breach_name: b?.Name || b?.Title || 'Unknown breach',
        first_seen: b?.BreachDate || b?.AddedDate || '',
        confidence: 90,
        verification: {
          evidence_level: 'level_1',
          notes: 'Match reported by HIBP breachedaccount endpoint (truncateResponse=true).'
        },
        url_reference: b?.Domain ? `https://${b.Domain}` : ''
      }))
    : [];

  return { enabled: true, email, matches, error: null };
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, time: nowIso() });
});

app.post('/api/intel', async (req, res) => {
  const parsed = IntelRequestSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({
      ok: false,
      error: 'Invalid request body',
      details: parsed.error.flatten()
    });
  }

  const input = parsed.data;
  const subjectName = buildSubjectName(input);
  const requestedEmails = (input.identifiers?.emails || []).filter(Boolean).slice(0, 5);

  if (!input.firstName && !input.lastName && !input.keywords && requestedEmails.length === 0) {
    return res.status(400).json({ ok: false, error: 'Provide at least a name, context, or an email identifier.' });
  }

  const checks = [];
  const matches = [];
  const errors = [];

  for (const email of requestedEmails) {
    // HIBP: defensive use only, redacted output
    const hibp = await hibpBreachedAccount(email);
    checks.push({ name: 'HIBP', enabled: hibp.enabled, status: hibp.error ? 'error' : 'ok' });
    if (hibp.error) errors.push({ source: 'HIBP', message: hibp.error });
    matches.push(...hibp.matches);
  }

  const risk = computeRisk(matches.length);

  const response = {
    ok: true,
    generated_at: nowIso(),
    subject: {
      name: subjectName,
      context: input.keywords || ''
    },
    risk_overview: risk,
    matches,
    recommended_next_steps: [
      'Enable MFA on all accounts and rotate passwords for affected services.',
      'If an organization/domain: enable domain-wide breach monitoring with a licensed provider.',
      'Review public profiles for overshared personal information.',
      'If you suspect active impersonation: document evidence and report to the platform(s).'
    ],
    limitations: [
      'This app does not crawl Tor/I2P or private communities.',
      'Results depend on which licensed APIs you configure (e.g., HIBP).',
      'No sensitive leak contents are returned; output is metadata-only and redacted.'
    ],
    recommended_sources: recommendedSources(),
    checks,
    errors
  };

  return res.json(response);
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`IndiaTrace backend running on http://127.0.0.1:${PORT}`);
});

