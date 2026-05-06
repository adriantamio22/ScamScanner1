import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import "dotenv/config";

const RATE_LIMIT = 25;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const ipMap = new Map<string, { count: number; resetAt: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipMap.entries()) {
    if (now > record.resetAt) ipMap.delete(ip);
  }
}, 10 * 60 * 1000);

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const record = ipMap.get(ip);
  if (!record || now > record.resetAt) {
    const resetAt = now + RATE_WINDOW_MS;
    ipMap.set(ip, { count: 1, resetAt });
    return { allowed: true, remaining: RATE_LIMIT - 1, resetAt };
  }
  if (record.count >= RATE_LIMIT) return { allowed: false, remaining: 0, resetAt: record.resetAt };
  record.count++;
  return { allowed: true, remaining: RATE_LIMIT - record.count, resetAt: record.resetAt };
}

async function vtGet(path: string, apiKey: string): Promise<any> {
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3${path}`, {
      headers: { "x-apikey": apiKey },
    });
    return res.ok ? await res.json() : null;
  } catch { return null; }
}

async function checkVTHash(hash: string, key: string): Promise<string> {
  const data = await vtGet(`/files/${hash}`, key);
  if (!data) return "[VIRUSTOTAL] Hash not found in database.";
  const s = data.data?.attributes?.last_analysis_stats ?? {};
  const name = data.data?.attributes?.meaningful_name || hash;
  const total = (s.malicious||0)+(s.suspicious||0)+(s.harmless||0)+(s.undetected||0);
  return `[VIRUSTOTAL_HASH] "${name}": ${s.malicious||0} malicious, ${s.suspicious||0} suspicious out of ${total} engines.`;
}

async function checkVTIP(ip: string, key: string): Promise<string> {
  const data = await vtGet(`/ip_addresses/${ip}`, key);
  if (!data) return "";
  const a = data.data?.attributes ?? {};
  const s = a.last_analysis_stats ?? {};
  const total = (s.malicious||0)+(s.suspicious||0)+(s.harmless||0)+(s.undetected||0);
  return `[VIRUSTOTAL_IP] ${ip}: ${s.malicious||0} malicious, ${s.suspicious||0} suspicious out of ${total} engines. Country: ${a.country||"Unknown"}. ASN: ${a.as_owner||"Unknown"}.`;
}

async function checkVTURL(url: string, key: string): Promise<string> {
  const urlId = Buffer.from(url).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
  const data = await vtGet(`/urls/${urlId}`, key);
  if (!data) return "[VIRUSTOTAL_URL] URL not in cache yet.";
  const s = data.data?.attributes?.last_analysis_stats ?? {};
  const total = (s.malicious||0)+(s.suspicious||0)+(s.harmless||0)+(s.undetected||0);
  return `[VIRUSTOTAL_URL] ${url}: ${s.malicious||0} malicious, ${s.suspicious||0} suspicious out of ${total} engines.`;
}

async function checkVTDomain(domain: string, key: string): Promise<string> {
  const data = await vtGet(`/domains/${domain}`, key);
  if (!data) return "";
  const a = data.data?.attributes ?? {};
  const s = a.last_analysis_stats ?? {};
  const total = (s.malicious||0)+(s.suspicious||0)+(s.harmless||0)+(s.undetected||0);
  const created = a.creation_date ? new Date(a.creation_date*1000).toISOString().split("T")[0] : "Unknown";
  return `[VIRUSTOTAL_DOMAIN] ${domain}: ${s.malicious||0} malicious, ${s.suspicious||0} suspicious out of ${total} engines. Registrar: ${a.registrar||"Unknown"}. Created: ${created}.`;
}

async function checkAbuseIPDB(ip: string, key: string): Promise<string> {
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { "Key": key, "Accept": "application/json" } }
    );
    if (!res.ok) return "";
    const d = (await res.json()).data;
    return `[ABUSEIPDB] ${ip}: Abuse score ${d.abuseConfidenceScore}%, ${d.totalReports} reports. ISP: ${d.isp}. Type: ${d.usageType}. Country: ${d.countryCode}.`;
  } catch { return ""; }
}

async function checkWHOIS(domain: string): Promise<string> {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return "";
    const data = await res.json();
    const events = data.events || [];
    const registered = events.find((e: any) => e.eventAction === "registration")?.eventDate;
    const expiry = events.find((e: any) => e.eventAction === "expiration")?.eventDate;
    const months = registered ? Math.floor((Date.now()-new Date(registered).getTime())/(1000*60*60*24*30)) : null;
    return `[WHOIS] ${domain}: Registered ${registered ? new Date(registered).toISOString().split("T")[0] : "Unknown"}. Expires ${expiry ? new Date(expiry).toISOString().split("T")[0] : "Unknown"}.${months !== null ? ` Domain age: ${months} months.` : ""}`;
  } catch { return ""; }
}

async function checkEmailDisify(email: string): Promise<string> {
  try {
    const res = await fetch(`https://disify.com/api/email/${encodeURIComponent(email)}`);
    if (!res.ok) return "";
    const d = await res.json();
    return `[EMAIL_CHECK] ${email}: Format valid=${d.format}, Disposable=${d.disposable}, DNS exists=${d.dns}, Whitelisted=${d.whitelisted}.`;
  } catch { return ""; }
}

async function checkHIBP(email: string, key: string): Promise<string> {
  if (!key) return "";
  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { headers: { "hibp-api-key": key, "user-agent": "ScamScanner-Forensic-Lab" } }
    );
    if (res.status === 404) return "[HIBP] No known data breaches found.";
    if (!res.ok) return "";
    const breaches = await res.json();
    return `[HIBP] ${breaches.length} breach(es): ${breaches.slice(0,5).map((b: any) => b.Name).join(", ")}${breaches.length > 5 ? " and more" : ""}.`;
  } catch { return ""; }
}

async function gatherRealData(type: string, input: string): Promise<string> {
  const vtKey = process.env.VIRUSTOTAL_API_KEY || "";
  const abuseKey = process.env.ABUSEIPDB_API_KEY || "";
  const hibpKey = process.env.HIBP_API_KEY || "";
  const results: string[] = [];
  const trimmedInput = input.trim();

  // Smart classification logic
  if (type === "LOOKUP") {
    if (/^[a-fA-F0-9]{32,64}$/.test(trimmedInput)) {
      results.push(`[CLASSIFICATION] Input identified as a cryptographic HASH (Malware Signature).`);
      if (vtKey) results.push(await checkVTHash(trimmedInput, vtKey));
      else results.push("[WARNING] VirusTotal API key missing. Unable to verify hash reputation.");
    } else {
      results.push(`[CLASSIFICATION] Input identified as a DOMAIN or HOSTNAME.`);
      if (vtKey) results.push(await checkVTDomain(trimmedInput, vtKey));
      results.push(await checkWHOIS(trimmedInput));
    }
  }

  if (type === "EMAIL") {
    results.push(`[CLASSIFICATION] Input identified as an EMAIL ADDRESS.`);
    results.push(await checkEmailDisify(trimmedInput));
    if (hibpKey) results.push(await checkHIBP(trimmedInput, hibpKey));
    else results.push("[INFO] HIBP API key missing. Skipping data breach correlation.");
    
    const domain = trimmedInput.split("@")[1];
    if (domain) {
      if (vtKey) results.push(await checkVTDomain(domain, vtKey));
      results.push(await checkWHOIS(domain));
    }
  }

  if (type === "IP") {
    results.push(`[CLASSIFICATION] Input identified as an IP ADDRESS.`);
    if (vtKey) results.push(await checkVTIP(trimmedInput, vtKey));
    if (abuseKey) results.push(await checkAbuseIPDB(trimmedInput, abuseKey));
    else results.push("[INFO] AbuseIPDB API key missing. Skipping IP reputation scoring.");
  }

  if (type === "WEBSITE") {
    results.push(`[CLASSIFICATION] Input identified as a WEBSITE URL.`);
    const domain = trimmedInput.replace(/^https?:\/\//, "").split("/")[0];
    if (vtKey) {
      results.push(await checkVTURL(trimmedInput, vtKey));
      results.push(await checkVTDomain(domain, vtKey));
    }
    results.push(await checkWHOIS(domain));
  }

  if (type === "EML") {
    results.push(`[CLASSIFICATION] Input identified as RAW EMAIL CONTENT / HEADERS.`);
    const ips = [...new Set(input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].slice(0, 3);
    const domainMatches = input.match(/(?:From|Reply-To|Return-Path)[^\n]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi) || [];
    const domains = [...new Set(domainMatches.map((m: string) => {
      const email = m.split('@')[1];
      return email ? email.trim() : "";
    }).filter(Boolean))].slice(0, 2) as string[];
    
    // Impersonation Check: Detect Display Name vs Email mismatch
    const fromLine = input.match(/From:.*<(.+@.+)>/i) || input.match(/From:\s*([^\n<]+)/i);
    const displayName = fromLine ? fromLine[1].split('<')[0].trim() : "";
    const emailMatch = input.match(/From:.*<(.+@.+)>/i);
    const actualEmail = emailMatch ? emailMatch[1] : "";
    
    if (displayName && actualEmail) {
      results.push(`[IDENTITY_ANALYSIS] Display Name: "${displayName}" | Actual Sender: ${actualEmail}`);
    }

    const replyToMatch = input.match(/Reply-To:\s*<(.+@.+)>/i) || input.match(/Reply-To:\s*(.+@.+)/i);
    if (replyToMatch && actualEmail && (replyToMatch[1] || replyToMatch[0]) !== actualEmail) {
      const replyEmail = replyToMatch[1] || replyToMatch[0];
      if (replyEmail.includes('@')) {
        results.push(`[SENSITIVE_SIGNAL] Reply-To mismatch detected. Replies are routed to: ${replyEmail}`);
      }
    }

    for (const ip of ips) {
      if (vtKey) results.push(await checkVTIP(ip, vtKey));
      if (abuseKey) results.push(await checkAbuseIPDB(ip, abuseKey));
    }
    for (const domain of domains) {
      if (vtKey) results.push(await checkVTDomain(domain, vtKey));
    }
  }

  return results.filter(Boolean).join("\n");
}

const SYSTEM_PROMPT = `You are ScamScanner, a digital forensic analyst. You receive REAL data from forensic APIs and your job is to interpret it clearly.

STRICT RULES:
- Base your verdict ONLY on the real API data shown in [BRACKETS]
- Do NOT invent data that was not returned by an API
- CRITICAL = VirusTotal detections > 2, AbuseIPDB score > 50, domain age < 7 days
- WARNING = 1-2 detections, AbuseIPDB score 10-50, domain age < 30 days, disposable email
- INFO = clean results, low scores, informational findings
- If no API data is available for something, set verdict to "NOT_FOUND" and legitimacyPercentage to 0.
- EMBRACE CROSS-REFERENCING: In the executiveSummary, emphasize that the results are based on cross-referencing multiple forensic intelligence sources. 
- AVOID REPETITION: Do not repeatedly mention specific tool names like "VirusTotal" or "AbuseIPDB" in every sentence of the summary. Use broader terms like "reputation engines", "global threat intelligence", or "forensic database correlation".
- IMPERSONATION RADAR: Specifically look for "Display Name Spoofing" where a trusted name is used with an unrelated email. Flag "Homoglyph Attacks" (look-alike characters like 'ο' vs 'o'). Check for high-risk BEC (Business Email Compromise) patterns like Reply-To mismatches or urgency in metadata.

Respond ONLY with this JSON:
{
  "entityType": "<Domain | Hash | IP | Email | URL | EML | Malware Signature | Intelligence Point>",
  "legitimacyPercentage": <0-100>,
  "verdict": "<MALICIOUS_THREAT | SUSPICIOUS_ACTIVITY | LEGIT_SIGNAL | NOT_FOUND>",
  "executiveSummary": "<2-3 sentences providing a high-level technical overview. Highlight the correlation between different intelligence sources without brand-dumping.>",
  "forensicSignals": [
    { "name": "<signal>", "severity": "<CRITICAL | WARNING | INFO>", "description": "<cite the real data>" }
  ]
}
If verdict is NOT_FOUND, forensicSignals can be an empty array.`;

function isRateLimitError(err: any): boolean {
  return err.message?.includes("429") || err.message?.includes("rate limit") || err.message?.includes("Rate limit") || err.message?.includes("TPD") || err.message?.includes("TPM");
}

async function callAI(url: string, apiKey: string, model: string, message: string): Promise<string> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: message },
      ],
      response_format: { type: "json_object" },
      max_tokens: 1024,
      temperature: 0.2,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `API error ${res.status}`);
  }
  const data = await res.json() as any;
  return data.choices[0].message.content;
}

async function callWithFallback(message: string): Promise<string> {
  const groqKey = process.env.GROQ_API_KEY;
  const orKey = process.env.OPENROUTER_API_KEY;

  // 1. Try Groq (Primary Fallback)
  if (groqKey) {
    try {
      return await callAI("https://api.groq.com/openai/v1/chat/completions", groqKey, "llama-3.1-8b-instant", message);
    } catch (err: any) {
      console.warn("Groq failed, trying OpenRouter...", err.message);
    }
  }

  // 3. Try OpenRouter (Tertiary - Fallback Models)
  if (orKey) {
    const fallbackModels = [
      "google/gemma-2-9b-it:free",
      "mistralai/mistral-7b-instruct:free",
      "meta-llama/llama-3.2-3b-instruct:free",
    ];

    for (const model of fallbackModels) {
      try {
        return await callAI("https://openrouter.ai/api/v1/chat/completions", orKey, model, message);
      } catch (err: any) {
        console.warn(`OpenRouter model ${model} failed, trying next...`);
        continue;
      }
    }
  }

  throw new Error("All AI providers are currently unavailable. Please try again later.");
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/gemini", async (req, res) => {
    const { action, type, input, message: fallbackMessage } = req.body ?? {};
    const clientIP = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.ip || "unknown";

    if (action === "status") {
      const keys = {
        gemini: !!process.env.GEMINI_API_KEY,
        virusTotal: !!process.env.VIRUSTOTAL_API_KEY,
        abuseIPDB: !!process.env.ABUSEIPDB_API_KEY,
        hibp: !!process.env.HIBP_API_KEY,
        groq: !!process.env.GROQ_API_KEY,
        openRouter: !!process.env.OPENROUTER_API_KEY,
      };
      
      const missingKeys = Object.entries(keys).filter(([_, set]) => !set).map(([name]) => name);
      
      return res.json({ 
        ok: true, 
        status: missingKeys.length > 0 ? "DEGRADED" : "OPERATIONAL",
        info: missingKeys.length > 0 ? `Missing keys: ${missingKeys.join(", ")}` : "All systems normal",
        authStatus: keys
      });
    }

    const { allowed, remaining, resetAt } = checkRateLimit(clientIP);
    if (!allowed) {
      const mins = Math.ceil((resetAt - Date.now()) / 60000);
      return res.status(429).json({
        error: "RATE_LIMITED",
        message: `Scan limit reached (${RATE_LIMIT} scans/hour). Try again in ${mins} minute${mins !== 1 ? "s" : ""}.`,
      });
    }

    if (action === "forensics" || action === "analyze") {
      try {
        const realData = await gatherRealData(type, input);
        return res.json({ success: true, realData, remaining });
      } catch (err: any) {
        console.error("Forensics failed:", err);
        return res.status(500).json({ error: err.message || "Forensics failed" });
      }
    }

    if (action === "analyze-fallback") {
      try {
        const rawJson = await callWithFallback(fallbackMessage);
        return res.json({ success: true, data: JSON.parse(rawJson), remaining });
      } catch (err: any) {
        console.error("Fallback analysis failed:", err);
        return res.status(500).json({ error: err.message || "Fallback analysis failed" });
      }
    }

    console.warn(`[API] Invalid action received: "${action}" from ${clientIP}`);
    return res.status(400).json({ error: "Invalid action", received: action });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: process.env.DISABLE_HMR !== 'true' },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
