const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

const ipMap = new Map<string, { count: number; resetAt: number }>();
const scanCache = new Map<string, { result: any; expiresAt: number }>();

// Cleanup intervals
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipMap.entries()) {
    if (now > record.resetAt) ipMap.delete(ip);
  }
  for (const [key, record] of scanCache.entries()) {
    if (now > record.expiresAt) scanCache.delete(key);
  }
}, 10 * 60 * 1000);

function getIP(req: any): string {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.socket.remoteAddress ||
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

// REAL DATA RESOURCES

async function callHIBP(email: string): Promise<string> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) return "";
  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { headers: { "hibp-api-key": apiKey, "user-agent": "ScamScanner-Forensic-Lab" } }
    );
    if (!res.ok) return "";
    const breaches = await res.json();
    return `[HIBP: ${breaches.length} breaches found: ${breaches.slice(0, 3).map((b: any) => b.Name).join(", ")}]`;
  } catch {
    return "";
  }
}

async function callDisify(email: string): Promise<string> {
  try {
    const apiKey = process.env.DISIFY_API_KEY;
    const url = `https://www.disify.com/api/email/${encodeURIComponent(email)}`;
    const headers: any = {};
    if (apiKey) {
      // Assuming Disify might use an API key in headers if configured
      headers["Authorization"] = `Bearer ${apiKey}`;
    }
    
    const res = await fetch(url, { headers });
    if (!res.ok) return "";
    const data = await res.json();
    return `[DISIFY: Format=${data.format}, Domain=${data.domain}, Disposable=${data.disposable}, DNS=${data.dns}, Whitelisted=${data.whitelisted}]`;
  } catch {
    return "";
  }
}

async function callVirusTotal(type: string, input: string): Promise<string> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return "";
  try {
    let endpoint = "";
    if (type === "IP") endpoint = `/ip_addresses/${input}`;
    else if (type === "WEBSITE") {
      const urlId = Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
      endpoint = `/urls/${urlId}`;
    } else if (type === "LOOKUP") endpoint = `/files/${input}`;
    else return "";

    const res = await fetch(`https://www.virustotal.com/api/v3${endpoint}`, {
      headers: { "x-apikey": apiKey },
    });
    if (!res.ok) return "";
    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) return "";
    return `[VIRUSTOTAL: Malicious=${stats.malicious}, Suspicious=${stats.suspicious}, Harmless=${stats.harmless}, Undetected=${stats.undetected}]`;
  } catch {
    return "";
  }
}

async function callAbuseIPDB(ip: string): Promise<string> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return "";
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}`, {
      headers: { "Key": apiKey, "Accept": "application/json" },
    });
    if (!res.ok) return "";
    const { data } = await res.json();
    return `[ABUSEIPDB: Confidence Score=${data.abuseConfidenceScore}%, Reports=${data.totalReports}, Country=${data.countryCode}, Usage=${data.usageType}]`;
  } catch {
    return "";
  }
}

const SYSTEM_PROMPT = `You are ScamScanner, a digital forensic assistant. You must only make claims supported by the provided REAL_CONTEXT or directly observable from USER_INPUT.

Return ONLY valid JSON in this exact shape:
{
  "legitimacyPercentage": <number 0-100>,
  "verdict": "<MALICIOUS_THREAT | SUSPICIOUS_ACTIVITY | LEGIT_SIGNAL>",
  "executiveSummary": "<summary>",
  "forensicSignals": [
    {
      "name": "<signal>",
      "severity": "<CRITICAL | WARNING | INFO>",
      "description": "<evidence-backed explanation>"
    }
  ]
}

Rules:
- Do not invent data.
- Do not guess exact breach counts, geolocation, domain age, WHOIS ownership, malware detections, blacklist status, abuse confidence scores, or mailbox existence.
- Only say mailbox existence is verified if a real email validation service confirms it.
- If only Disify is available, describe the result as basic email validation unless it explicitly confirms deliverability.
- If real context is missing, say the analysis is heuristic or limited.
- Every forensic signal must be tied to REAL_CONTEXT, USER_INPUT, or clearly labeled as heuristic.
- Output JSON only.
- No markdown.
- No code fences.
- No extra text.`;

function isProviderError(err: any): boolean {
  const msg = (err.message || "").toLowerCase();
  return (
    msg.includes("429") ||
    msg.includes("rate limit") ||
    msg.includes("quota") ||
    msg.includes("tpd") ||
    msg.includes("tpm") ||
    msg.includes("unavailable") ||
    msg.includes("overloaded") ||
    msg.includes("rate_limit")
  );
}

async function callAIProvider(url: string, apiKey: string, model: string, message: string): Promise<string> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://ai.studio/build",
      "X-Title": "ScamScanner",
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: message },
      ],
      max_tokens: 1024,
      temperature: 0.1, // Lower temperature for more consistent JSON
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `API error ${res.status}`);
  }

  const data = await res.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error("Empty response from AI provider");
  return content;
}

async function performAnalysisWithFallback(message: string): Promise<{ data: string; provider: string; model: string }> {
  const groqKey = process.env.GROQ_API_KEY;
  const openrouterKey = process.env.OPENROUTER_API_KEY;

  if (!groqKey && !openrouterKey) {
    throw new Error("No AI provider keys configured. Add GROQ_API_KEY or OPENROUTER_API_KEY in Vercel.");
  }

  // 1. Primary: Groq
  if (groqKey) {
    const groqModel = "llama-3.1-8b-instant";
    try {
      const result = await callAIProvider(
        "https://api.groq.com/openai/v1/chat/completions",
        groqKey,
        groqModel,
        message
      );
      return { data: result, provider: "groq", model: groqModel };
    } catch (err) {
      if (!isProviderError(err)) throw err;
      console.warn("Groq failed/rate-limited, falling back to OpenRouter...");
    }
  }

  // 2. Secondary: OpenRouter Fallbacks
  if (openrouterKey) {
    const models = [
      "google/gemini-2.0-flash-exp:free",
      "meta-llama/llama-3.2-3b-instruct:free",
      "meta-llama/llama-3.1-8b-instruct:free",
      "google/gemma-2-9b-it:free",
      "mistralai/mistral-7b-instruct:free",
      "openrouter/auto" // Let OpenRouter decide if others fail
    ];

    for (const model of models) {
      try {
        const result = await callAIProvider(
          "https://openrouter.ai/api/v1/chat/completions",
          openrouterKey,
          model,
          message
        );
        return { data: result, provider: "openrouter", model: model };
      } catch (err: any) {
        console.warn(`OpenRouter fallback model ${model} failed: ${err.message}`);
      }
    }
  }

  throw new Error("All AI providers (Groq and OpenRouter) are currently unavailable. Please try again later.");
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { action, type, input } = req.body ?? {};

  // Alias Resolution
  const resolvedAction = 
    action === "health" ? "status" :
    action === "scan" ? "analyze" :
    action === "email_context" ? "hibp" :
    action;

  if (resolvedAction === "hibp") {
    try {
      const results = [];
      if (type === "EMAIL" || type === "MAILBOX") {
        results.push(await callHIBP(input));
        results.push(await callDisify(input));
      }
      return res.json({ context: results.filter(Boolean).join("\n") });
    } catch {
      return res.status(500).json({ error: "Context gathering failed" });
    }
  }

  if (resolvedAction === "status") {
    try {
      const { provider, model } = await performAnalysisWithFallback("hi");
      return res.json({ ok: true, status: "OPERATIONAL", provider, model });
    } catch (err: any) {
      return res.json({ ok: false, status: "API_ERROR", message: err.message });
    }
  }

  if (resolvedAction === "analyze") {
    const normalizedInput = String(input || "").trim();
    const cacheKey = `${type}:${normalizedInput}`;
    const cached = scanCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return res.json({ success: true, data: cached.result, cached: true });
    }

    const ip = getIP(req);
    const { allowed, remaining, resetAt } = checkRateLimit(ip);

    if (!allowed) {
      const mins = Math.ceil((resetAt - Date.now()) / 60000);
      return res.status(429).json({
        error: "RATE_LIMITED",
        message: `Scan limit reached (${RATE_LIMIT} scans/hour). Try again in ${mins} minute${mins !== 1 ? "s" : ""}.`,
      });
    }

    try {
      // Gather REAL_CONTEXT
      const contextParts = [];
      if (type === "EMAIL" || type === "MAILBOX") {
        contextParts.push(await callDisify(normalizedInput));
        contextParts.push(await callHIBP(normalizedInput));
      } else if (type === "IP") {
        contextParts.push(await callAbuseIPDB(normalizedInput));
        contextParts.push(await callVirusTotal("IP", normalizedInput));
      } else if (type === "WEBSITE") {
        contextParts.push(await callVirusTotal("WEBSITE", normalizedInput));
      } else if (type === "LOOKUP") {
        contextParts.push(await callVirusTotal("LOOKUP", normalizedInput));
      }

      const realContext = contextParts.filter(Boolean).join("\n") || "No real API data available for this input.";
      
      const prompt = `REAL_CONTEXT:\n${realContext}\n\nUSER_INPUT:\n${normalizedInput}\n\nSCAN_TYPE:\n${type}`;

      const { data: rawJson, provider } = await performAnalysisWithFallback(prompt);
      
      const jsonMatch = rawJson.match(/\{[\s\S]*\}/);
      const cleanedJson = JSON.parse(jsonMatch ? jsonMatch[0] : rawJson);
      
      scanCache.set(cacheKey, { result: cleanedJson, expiresAt: Date.now() + CACHE_TTL_MS });
      
      return res.json({ success: true, data: cleanedJson, provider, remaining });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || "Analysis failed" });
    }
  }

  return res.status(400).json({ 
    error: "Invalid action", 
    expectedActions: ["status", "hibp", "analyze"],
    receivedAction: action
  });
}


