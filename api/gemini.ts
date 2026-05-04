const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const ipMap = new Map<string, { count: number; resetAt: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipMap.entries()) {
    if (now > record.resetAt) ipMap.delete(ip);
  }
}, 10 * 60 * 1000);

function getIP(req: any): string {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    "unknown"
  );
}

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const record = ipMap.get(ip);
  if (!record || now > record.resetAt) {
    const resetAt = now + RATE_WINDOW_MS;
    ipMap.set(ip, { count: 1, resetAt });
    return { allowed: true, remaining: RATE_LIMIT - 1, resetAt };
  }
  if (record.count >= RATE_LIMIT) {
    return { allowed: false, remaining: 0, resetAt: record.resetAt };
  }
  record.count++;
  return { allowed: true, remaining: RATE_LIMIT - record.count, resetAt: record.resetAt };
}

async function callHIBP(email: string): Promise<any[]> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) return [];
  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { headers: { "hibp-api-key": apiKey, "user-agent": "ScamScanner-Forensic-Lab" } }
    );
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

const SYSTEM_PROMPT = `You are the core engine of ScamScanner, a Digital Forensic Lab.
Analyze the given input and respond ONLY with a valid JSON object in this exact format:
{
  "legitimacyPercentage": <number 0-100>,
  "verdict": "<MALICIOUS_THREAT | SUSPICIOUS_ACTIVITY | LEGIT_SIGNAL>",
  "executiveSummary": "<concise forensic overview>",
  "forensicSignals": [
    { "name": "<signal name>", "severity": "<CRITICAL | WARNING | INFO>", "description": "<detail>" }
  ]
}

You analyze:
1. Mailbox Checker: email safety, MX/SPF/DMARC records, malicious attachments/links.
2. Email Address Verifier: syntax, mailbox existence, disposable/burner status, spoofing reputation.
3. IP Analysis: VPN/Proxy/Tor exit nodes, abuse confidence scores, geolocation/ISP data.
4. Website Checker: URL safety, SSL certificates, phishing patterns, domain age/reputation.
5. EML Investigator: raw email headers, spoofed From addresses, Reply-To mismatches, embedded link risk.

Always respond with ONLY the JSON object, no extra text.`;

function isRateLimitError(err: any): boolean {
  return (
    err.message?.includes("429") ||
    err.message?.includes("rate limit") ||
    err.message?.includes("Rate limit") ||
    err.message?.includes("quota") ||
    err.message?.includes("TPD") ||
    err.message?.includes("TPM")
  );
}

async function callAI(url: string, apiKey: string, model: string, message: string): Promise<string> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: message },
      ],
      response_format: { type: "json_object" },
      max_tokens: 1024,
      temperature: 0.3,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `API error ${res.status}`);
  }

  const data = await res.json();
  return data.choices[0].message.content;
}

async function callWithFallback(message: string): Promise<string> {
  const groqKey = process.env.GROQ_API_KEY;
  const openrouterKey = process.env.OPENROUTER_API_KEY;

  if (groqKey) {
    try {
      return await callAI(
        "https://api.groq.com/openai/v1/chat/completions",
        groqKey,
        "llama-3.1-8b-instant",
        message
      );
    } catch (err: any) {
      if (!isRateLimitError(err)) throw err;
    }
  }

  if (openrouterKey) {
    return await callAI(
      "https://openrouter.ai/api/v1/chat/completions",
      openrouterKey,
      "meta-llama/llama-3.1-8b-instruct:free",
      message
    );
  }

  throw new Error("No AI providers available. Check your API keys in Vercel settings.");
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { action, type, input } = req.body ?? {};

  if (action === "hibp") {
    try {
      const breaches = await callHIBP(input);
      const hibpContext = breaches.length > 0
        ? `\n[HIBP: ${breaches.length} breach(es) found: ${breaches.slice(0, 5).map((b: any) => b.Name).join(", ")}${breaches.length > 5 ? " and more" : ""}]`
        : `\n[HIBP: No known breaches found]`;
      return res.json({ context: hibpContext });
    } catch {
      return res.status(500).json({ error: "HIBP check failed" });
    }
  }

  if (action === "status") {
    try {
      await callWithFallback("hi");
      return res.json({ ok: true, status: "OPERATIONAL" });
    } catch {
      return res.json({ ok: false, status: "API_ERROR" });
    }
  }

  if (action === "analyze") {
    const ip = getIP(req);
    const { allowed, remaining, resetAt } = checkRateLimit(ip);

    if (!allowed) {
      const minutesLeft = Math.ceil((resetAt - Date.now()) / 60000);
      return res.status(429).json({
        error: "RATE_LIMITED",
        message: `Scan limit reached (${RATE_LIMIT} scans/hour). Try again in ${minutesLeft} minute${minutesLeft !== 1 ? "s" : ""}.`,
      });
    }

    try {
      const rawJson = await callWithFallback(
        `Analyze this ${type} input: ${input}. Perform a deep forensic simulation.`
      );
      return res.json({ success: true, data: JSON.parse(rawJson), remaining });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || "Analysis failed" });
    }
  }

  return res.status(400).json({ error: "Invalid action" });
}
