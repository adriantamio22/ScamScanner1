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

async function callDisify(email: string): Promise<string> {
  try {
    const res = await fetch(`https://www.disify.com/api/email/${encodeURIComponent(email)}`);
    if (!res.ok) return "";
    const data = await res.json();
    return `[DISIFY: Format Valid=${data.format}, Disposable=${data.disposable}, DNS Valid=${data.dns}]`;
  } catch {
    return "";
  }
}

const SYSTEM_PROMPT = `You are ScamScanner, a Digital Forensic Analyst.
Analyze the given input and respond ONLY with a valid JSON object in this exact format:
{
  "legitimacyPercentage": <number 0-100>,
  "verdict": "<MALICIOUS_THREAT | SUSPICIOUS_ACTIVITY | LEGIT_SIGNAL>",
  "executiveSummary": "<concise forensic overview>",
  "forensicSignals": [
    { "name": "<signal name>", "severity": "<CRITICAL | WARNING | INFO>", "description": "<detail>" }
  ]
}

STRICT GUIDELINES:
1. Do NOT invent/hallucinate forensic data. Only use provided context (HIBP, Disify, or headers).
2. If real API context is missing, describe your analysis as "heuristic-based".
3. Do NOT mention specific tool names (HIBP, Disify) in the final verdict; use terms like "threat intelligence" or "mailbox verification".
4. Respond with ONLY the JSON object.`;

function isProviderError(err: any): boolean {
  const msg = (err.message || "").toLowerCase();
  return (
    msg.includes("429") ||
    msg.includes("rate limit") ||
    msg.includes("quota") ||
    msg.includes("tpd") ||
    msg.includes("tpm") ||
    msg.includes("unavailable") ||
    msg.includes("overloaded")
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

async function performAnalysisWithFallback(message: string): Promise<{ data: any; provider: string }> {
  const groqKey = process.env.GROQ_API_KEY;
  const openrouterKey = process.env.OPENROUTER_API_KEY;

  if (!groqKey && !openrouterKey) {
    throw new Error("No AI provider keys configured. Add GROQ_API_KEY or OPENROUTER_API_KEY in Vercel.");
  }

  // 1. Primary: Groq
  if (groqKey) {
    try {
      const result = await callAIProvider(
        "https://api.groq.com/openai/v1/chat/completions",
        groqKey,
        "llama-3.1-8b-instant",
        message
      );
      return { data: result, provider: "groq" };
    } catch (err) {
      if (!isProviderError(err)) throw err;
      console.warn("Groq failed/rate-limited, falling back...");
    }
  }

  // 2. Secondary: OpenRouter Fallbacks
  if (openrouterKey) {
    const models = [
      "meta-llama/llama-3.1-8b-instruct:free",
      "google/gemma-2-9b-it:free",
      "mistralai/mistral-7b-instruct:free",
    ];

    for (const model of models) {
      try {
        const result = await callAIProvider(
          "https://openrouter.ai/api/v1/chat/completions",
          openrouterKey,
          model,
          message
        );
        return { data: result, provider: `openrouter:${model}` };
      } catch (err) {
        console.warn(`Fallback model ${model} failed, trying next...`);
      }
    }
  }

  throw new Error("All AI providers are currently unavailable.");
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
      const breaches = await callHIBP(input);
      const disify = await callDisify(input);
      const hibpContext = breaches.length > 0
        ? `\n[HIBP: ${breaches.length} breach(es) found: ${breaches.slice(0, 5).map((b: any) => b.Name).join(", ")}]`
        : `\n[HIBP: No known breaches found]`;
      return res.json({ context: `${hibpContext}\n${disify}` });
    } catch {
      return res.status(500).json({ error: "HIBP check failed" });
    }
  }

  if (resolvedAction === "status") {
    try {
      await performAnalysisWithFallback("hi");
      return res.json({ ok: true, status: "OPERATIONAL" });
    } catch (err: any) {
      return res.json({ ok: false, status: "API_ERROR", message: err.message });
    }
  }

  if (resolvedAction === "analyze") {
    const cacheKey = `${type}:${input}`;
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
      const { data: rawJson, provider } = await performAnalysisWithFallback(
        `Analyze this ${type} input: ${input}. Perform a deep forensic simulation.`
      );
      
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

