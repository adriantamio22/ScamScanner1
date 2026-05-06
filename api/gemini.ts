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

// Input type detection helpers
const PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  IP: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
  MD5: /^[a-fA-F0-9]{32}$/,
  SHA1: /^[a-fA-F0-9]{40}$/,
  SHA256: /^[a-fA-F0-9]{64}$/,
  URL: /^https?:\/\/[^\s$.?#].[^\s]*$/i,
  DOMAIN: /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/
};

function detectInputType(input: string): string {
  const trimmed = input.trim();
  if (PATTERNS.EMAIL.test(trimmed)) return "EMAIL";
  if (PATTERNS.IP.test(trimmed)) return "IP";
  if (PATTERNS.SHA256.test(trimmed)) return "SHA256";
  if (PATTERNS.SHA1.test(trimmed)) return "SHA1";
  if (PATTERNS.MD5.test(trimmed)) return "MD5";
  if (PATTERNS.URL.test(trimmed)) return "URL";
  if (PATTERNS.DOMAIN.test(trimmed)) return "DOMAIN";
  if (trimmed.length > 100 && (trimmed.toLowerCase().includes("received:") || trimmed.toLowerCase().includes("return-path:"))) return "EML";
  return "UNKNOWN";
}

// REAL DATA RESOURCES

async function callDisify(email: string): Promise<string> {
  const apiKey = process.env.DISIFY_API_KEY;
  const url = `https://www.disify.com/api/email/${encodeURIComponent(email)}`;
  const headers: any = {};
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
  
  try {
    const res = await fetch(url, { headers });
    if (!res.ok) return "";
    const data = await res.json();
    return `[DISIFY: FormatValid=${data.format}, Domain=${data.domain}, Disposable=${data.disposable}, DNSValid=${data.dns}, Deliverable=${data.whitelisted ? "Likely" : "Unknown"}]`;
  } catch {
    return "";
  }
}

async function callVirusTotal(type: 'file' | 'ip' | 'url' | 'domain', input: string): Promise<string> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return "";
  const normalized = input.toLowerCase().trim();
  
  try {
    let endpoint = "";
    if (type === 'file') endpoint = `/files/${normalized}`;
    else if (type === 'ip') endpoint = `/ip_addresses/${normalized}`;
    else if (type === 'domain') endpoint = `/domains/${normalized}`;
    else if (type === 'url') {
      const urlId = Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
      endpoint = `/urls/${urlId}`;
    }

    const res = await fetch(`https://www.virustotal.com/api/v3${endpoint}`, {
      headers: { "x-apikey": apiKey },
    });
    
    if (res.status === 404) return `[VIRUSTOTAL: No intelligence report found for ${normalized}]`;
    if (!res.ok) return `[VIRUSTOTAL: API Error ${res.status}]`;
    
    const data = await res.json();
    const attrs = data.data?.attributes;
    const stats = attrs?.last_analysis_stats;
    if (!stats) return "";
    
    let info = `[VIRUSTOTAL: Malicious=${stats.malicious}, Suspicious=${stats.suspicious}, Harmless=${stats.harmless}, Undetected=${stats.undetected}]`;
    
    if (attrs.last_analysis_results?.Microsoft) {
      info += ` [Microsoft Intelligence: ${attrs.last_analysis_results.Microsoft.result}]`;
    }
    if (attrs.names?.[0]) info += ` [Filename: ${attrs.names[0]}]`;
    if (attrs.whois) info += ` [WHOIS snippet: ${attrs.whois.substring(0, 100).replace(/\n/g, " ")}...]`;
    
    return info;
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
    return `[ABUSEIPDB: Score=${data.abuseConfidenceScore}%, Reports=${data.totalReports}, Country=${data.countryCode}, LastReported=${data.lastReportedAt || "never"}]`;
  } catch {
    return "";
  }
}

async function callRDAP(domain: string): Promise<string> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (!res.ok) return "";
    const data = await res.json();
    const events = data.events || [];
    const registration = events.find((e: any) => e.eventAction === 'registration');
    return `[RDAP: RegisteredAt=${registration?.eventDate || "unknown"}, Registrar=${data.port43 || "unknown"}]`;
  } catch {
    return "";
  }
}

const SYSTEM_PROMPT = `You are ScamScanner, a digital forensic assistant. You must only make claims supported by REAL_CONTEXT or directly observable from USER_INPUT.

Return ONLY valid JSON in this exact format:
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
  ],
  "sourcesChecked": ["<source names>"],
  "limitations": ["<missing or unavailable sources>"]
}

Rules:
- Do not invent data.
- Do not guess VirusTotal detections. Cite VT if provided.
- Do not guess AbuseIPDB scores. Cite AbuseIPDB if provided.
- Do not guess mailbox existence.
- Do not guess WHOIS/domain age.
- Do not guess Microsoft malware intelligence results.
- If a source is unavailable or missing from REAL_CONTEXT, list it in limitations.
- If no source confirms maliciousness, do not call it malicious.
- If evidence is limited, say the result is heuristic.
- Every forensic signal must cite a source name or say “heuristic”.
- Output JSON only. No markdown. No code fences.`;

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
      temperature: 0.1,
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

async function performAnalysisWithFallback(message: string): Promise<{ data: string; provider: string; model: string; errors?: any }> {
  const groqKey = process.env.GROQ_API_KEY;
  const openrouterKey = process.env.OPENROUTER_API_KEY;

  if (!groqKey && !openrouterKey) {
    throw new Error("No AI provider keys configured. Add GROQ_API_KEY or OPENROUTER_API_KEY in Vercel.");
  }

  const providerErrors: any = {};

  if (groqKey) {
    const model = "llama-3.1-8b-instant";
    try {
      const result = await callAIProvider("https://api.groq.com/openai/v1/chat/completions", groqKey, model, message);
      return { data: result, provider: "groq", model };
    } catch (err: any) {
      providerErrors.groq = err.message;
      console.warn("Groq failed, trying OpenRouter...");
    }
  }

  if (openrouterKey) {
    const models = [
      "meta-llama/llama-3.1-8b-instruct:free",
      "google/gemma-2-9b-it:free",
      "mistralai/mistral-7b-instruct:free",
      "openrouter/auto"
    ];

    for (const model of models) {
      try {
        const result = await callAIProvider("https://openrouter.ai/api/v1/chat/completions", openrouterKey, model, message);
        return { data: result, provider: "openrouter", model };
      } catch (err: any) {
        if (!providerErrors.openrouter) providerErrors.openrouter = [];
        providerErrors.openrouter.push(`${model}: ${err.message}`);
      }
    }
  }

  const error: any = new Error("All AI providers are currently unavailable.");
  error.providerErrors = providerErrors;
  throw error;
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { action, type, input } = (req.body || {}) as { action?: string; type?: string; input?: string };
  const resolvedAction = (action === "health" ? "status" : action === "scan" ? "analyze" : action) || "";

  if (resolvedAction === "status") {
    try {
      const { provider, model } = await performAnalysisWithFallback("hi");
      return res.json({ ok: true, status: "OPERATIONAL", provider, model });
    } catch (err: any) {
      return res.json({ ok: false, status: "API_ERROR", message: err.message, errors: err.providerErrors });
    }
  }

  if (resolvedAction === "analyze") {
    if (!input || !type) return res.status(400).json({ error: "Missing type or input" });
    
    // Check type compatibility
    const detected = detectInputType(input);
    const isValid = 
      (type === "EMAIL" && detected === "EMAIL") ||
      (type === "IP" && detected === "IP") ||
      (type === "LOOKUP" && ["SHA256", "SHA1", "MD5", "DOMAIN", "URL", "IP"].includes(detected)) ||
      (type === "WEBSITE" && ["URL", "DOMAIN"].includes(detected)) ||
      (type === "EML" && detected === "EML");

    if (!isValid && detected !== "UNKNOWN") {
      return res.status(400).json({
        error: "WRONG_INPUT_TYPE",
        message: `This looks like ${detected}. Please use the appropriate tab.`
      });
    }

    const normalizedInput = input.trim();
    const cacheKey = `${type}:${normalizedInput}`;
    const cached = scanCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) return res.json({ success: true, data: cached.result, cached: true });

    const ip = getIP(req);
    const { allowed, remaining, resetAt } = checkRateLimit(ip);
    if (!allowed) {
      return res.status(429).json({
        error: "RATE_LIMITED",
        message: `Scan limit reached (5 scans/hour). Try again in ${Math.ceil((resetAt - Date.now()) / 60000)} minutes.`
      });
    }

    try {
      const contextParts: string[] = [];
      const sourcesUsed: string[] = [];
      const limitations: string[] = [];

      // 1. DISIFY
      if (detected === "EMAIL") {
        const d = await callDisify(normalizedInput);
        if (d) { contextParts.push(d); sourcesUsed.push("Disify"); }
        else limitations.push("Disify unavailable");
      }

      // 2. VIRUSTOTAL
      const vtType = 
        detected === "IP" ? "ip" : 
        detected === "DOMAIN" ? "domain" : 
        detected === "URL" ? "url" : 
        ["SHA256", "SHA1", "MD5"].includes(detected) ? "file" : 
        null;
      
      if (vtType) {
        const vt = await callVirusTotal(vtType, normalizedInput);
        if (vt) { contextParts.push(vt); sourcesUsed.push("VirusTotal"); }
        else limitations.push("VirusTotal unavailable or no record");
      }

      // 3. ABUSEIPDB
      if (detected === "IP") {
        const a = await callAbuseIPDB(normalizedInput);
        if (a) { contextParts.push(a); sourcesUsed.push("AbuseIPDB"); }
        else limitations.push("AbuseIPDB unavailable");
      }

      // 4. RDAP
      if (detected === "DOMAIN") {
        const r = await callRDAP(normalizedInput);
        if (r) { contextParts.push(r); sourcesUsed.push("RDAP"); }
        else limitations.push("RDAP unavailable");
      }

      // 5. EML EXTRACTION
      if (detected === "EML") {
        const urls = [...new Set(normalizedInput.match(/https?:\/\/[^\s"'<>]+(?:\.[a-z]{2,})/gi) || [])].slice(0, 2);
        const ips = [...new Set(normalizedInput.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g) || [])].slice(0, 2);
        for (const url of urls) {
          const v = await callVirusTotal("url", url);
          if (v) contextParts.push(`[EML_URL: ${url}] ${v}`);
        }
        for (const i of ips) {
          const a = await callAbuseIPDB(i);
          if (a) contextParts.push(`[EML_IP: ${i}] ${a}`);
        }
        sourcesUsed.push("Header Analysis");
      }

      const realContext = contextParts.filter(Boolean).join("\n") || "No real API data available. Analysis will be heuristic.";
      const prompt = `REAL_CONTEXT:\n${realContext}\n\nUSER_INPUT:\n${normalizedInput}\n\nSCAN_TYPE:\n${type}\n\nSOURCES_USED:\n${sourcesUsed.join(", ")}\n\nLIMITATIONS:\n${limitations.join(", ")}`;

      const { data: rawJson, provider } = await performAnalysisWithFallback(prompt);
      const jsonMatch = rawJson.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error("AI provider returned non-JSON response.");
      
      const result = JSON.parse(jsonMatch[0]);
      scanCache.set(cacheKey, { result, expiresAt: Date.now() + CACHE_TTL_MS });

      return res.json({ success: true, data: result, provider, remaining });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || "Analysis failed", providerErrors: err.providerErrors });
    }
  }

  return res.status(400).json({ 
    error: "Invalid action", 
    expectedActions: ["status", "analyze"],
    receivedAction: action 
  });
}


