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
  IP: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
  MD5: /^[a-fA-F0-9]{32}$/,
  SHA1: /^[a-fA-F0-9]{40}$/,
  SHA256: /^[a-fA-F0-9]{64}$/,
  URL: /^https?:\/\/[^\s$.?#].[^\s]*$/i,
  DOMAIN: /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/
};

function detectInputType(input: string): string {
  const trimmed = input.trim();
  if (PATTERNS.IP.test(trimmed)) return "IP";
  if (PATTERNS.EMAIL.test(trimmed)) return "EMAIL";
  if (PATTERNS.SHA256.test(trimmed)) return "SHA256";
  if (PATTERNS.SHA1.test(trimmed)) return "SHA1";
  if (PATTERNS.MD5.test(trimmed)) return "MD5";
  if (PATTERNS.URL.test(trimmed)) return "URL";
  if (PATTERNS.DOMAIN.test(trimmed)) return "DOMAIN";
  if (trimmed.length > 100 && (trimmed.toLowerCase().includes("received:") || trimmed.toLowerCase().includes("return-path:"))) return "EML";
  return "UNKNOWN";
}

function isPrivateIP(ip: string): boolean {
  // IPv4 Private & Reserved
  if (/^(127\.|10\.|169\.254\.)/.test(ip)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith('192.168.')) return true;
  // IPv6 Private & Reserved
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd00:')) return true;
  return false;
}

// REAL DATA RESOURCES

async function callDisify(email: string): Promise<any> {
  const apiKey = process.env.DISIFY_API_KEY;
  const url = `https://www.disify.com/api/email/${encodeURIComponent(email)}`;
  const headers: any = {};
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
  
  try {
    const res = await fetch(url, { headers });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function callVirusTotal(type: 'file' | 'ip' | 'url' | 'domain', input: string): Promise<any> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;
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
    
    if (!res.ok) return null;
    const data = await res.json();
    return data.data?.attributes;
  } catch {
    return null;
  }
}

async function callAbuseIPDB(ip: string): Promise<any> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return null;
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}`, {
      headers: { "Key": apiKey, "Accept": "application/json" },
    });
    if (!res.ok) return null;
    const { data } = await res.json();
    return data;
  } catch {
    return null;
  }
}

async function callRDAP(domain: string): Promise<any> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

const SYSTEM_PROMPT = `You are ScamScanner, a digital forensic assistant. You must only make claims supported by REAL_CONTEXT or directly observable from USER_INPUT.

Return ONLY valid JSON in this exact format:
{
  "legitimacyPercentage": <number 0-100>,
  "verdict": "<MALICIOUS_THREAT | SUSPICIOUS_ACTIVITY | LEGIT_SIGNAL>",
  "executiveSummary": "<clear explanation with the most important evidence>",
  "forensicSignals": [
    {
      "name": "<specific signal name>",
      "severity": "<CRITICAL | WARNING | INFO>",
      "description": "<detailed evidence-backed explanation citing exact facts from sources>",
      "source": "<VirusTotal | AbuseIPDB | Disify | WHOIS/RDAP | EML Parser | Heuristic>"
    }
  ],
  "sourcesChecked": ["<source names>"],
  "limitations": ["<what was not checked or unavailable>"],
  "recommendedActions": ["<practical next steps>"]
}

Rules:
- Do not invent data. Use ONLY provided facts.
- Do not produce generic descriptions like "based on VirusTotal."
- Cite exact returned facts: counts, dates, engine names, scores, or extracted headers.
- If a value is missing from REAL_CONTEXT, do not guess it.
- Use the PROVIDED Verdict and Legitimacy Score. Do not override them.
- AI must explain the significance of the facts in the forensicSignals and executiveSummary.
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
      max_tokens: 1536,
      temperature: 0.1,
      response_format: { type: "json_object" }
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

function getOrgDomain(domain?: string): string {
  if (!domain) return "";
  const parts = domain.toLowerCase().trim().split(".");
  if (parts.length <= 2) return parts.join(".");
  // Special handling for common 2-part TLDs if needed, but for general alignment:
  return parts.slice(-2).join(".");
}

function extractEmailAddress(str?: string): string {
  if (!str) return "";
  const match = str.match(/<([^>]+)>/) || str.match(/([^\s@]+@[^\s@]+\.[^\s@]+)/);
  return (match ? match[1] : str).toLowerCase().trim();
}

function getEmailDomain(email: string): string {
  return email.split("@")[1] || "";
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
      
      let calculatedVerdict = "LEGIT_SIGNAL";
      let calculatedPercentage = 100;
      const baseSignals: any[] = [];

      // 1. DISIFY
      if (detected === "EMAIL") {
        const d = await callDisify(normalizedInput);
        if (d) {
          sourcesUsed.push("Disify");
          const reasons = [];
          if (d.disposable) reasons.push("Disposable domain detected");
          if (!d.format) reasons.push("Invalid syntax");
          if (!d.dns) reasons.push("Missing DNS records");

          contextParts.push(`[SOURCE: Disify] Result: FormatValid=${d.format}, Domain=${d.domain}, Disposable=${d.disposable}, DNSValid=${d.dns}, Whitelisted=${d.whitelisted}`);
          
          if (reasons.length > 0) {
            calculatedVerdict = "SUSPICIOUS_ACTIVITY";
            calculatedPercentage = Math.min(calculatedPercentage, 40);
            baseSignals.push({
              name: "Email Reputation Factors",
              severity: "WARNING",
              description: `Disify identified risk factors: ${reasons.join(", ")}. Email domain uses ${d.disposable ? "a burner/disposable" : "a verifiable"} service.`,
              source: "Disify"
            });
          }
        } else {
          limitations.push("Disify unavailable");
        }
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
        if (vt && vt.last_analysis_stats) {
          sourcesUsed.push("VirusTotal");
          const s = vt.last_analysis_stats;
          const total = s.malicious + s.suspicious + s.harmless + s.undetected;
          
          let engineDetails = "";
          if (vt.last_analysis_results) {
            const flaggers = Object.entries(vt.last_analysis_results)
              .filter(([_, r]: [string, any]) => r.category === "malicious" || r.category === "suspicious")
              .map(([name, r]: [string, any]) => `${name} (${r.result || r.category})`)
              .join(", ");
            if (flaggers) engineDetails = ` Flagged by: ${flaggers}.`;
          }

          contextParts.push(`[SOURCE: VirusTotal] Stats: Malicious=${s.malicious}, Suspicious=${s.suspicious}, Harmless=${s.harmless}, Undetected=${s.undetected}. TotalEngines=${total}.${engineDetails}`);
          if (vt.names) contextParts.push(`[SOURCE: VirusTotal] Known Names: ${vt.names.join(", ")}`);
          if (vt.type_description) contextParts.push(`[SOURCE: VirusTotal] Type: ${vt.type_description}`);
          if (vt.size) contextParts.push(`[SOURCE: VirusTotal] Size: ${vt.size} bytes`);
          if (vt.categories) contextParts.push(`[SOURCE: VirusTotal] Categories: ${Object.values(vt.categories).join(", ")}`);
          if (vt.reputation) contextParts.push(`[SOURCE: VirusTotal] Internal Reputation Score: ${vt.reputation}`);

          if (total > 0) {
            const vtPercentage = Math.round(((s.harmless + s.undetected) / total) * 100);
            calculatedPercentage = Math.min(calculatedPercentage, vtPercentage);
          } else {
            limitations.push("VirusTotal returned no engine statistics.");
            calculatedPercentage = Math.min(calculatedPercentage, 50);
          }

          if (s.malicious >= 3) calculatedVerdict = "MALICIOUS_THREAT";
          else if (s.malicious > 0 || s.suspicious > 0) {
            if (calculatedVerdict !== "MALICIOUS_THREAT") calculatedVerdict = "SUSPICIOUS_ACTIVITY";
          }

          baseSignals.push({
            name: "Multi-Engine Threat Detection",
            severity: s.malicious >= 3 ? "CRITICAL" : (s.malicious > 0 ? "WARNING" : "INFO"),
            description: `Detection Ratio: ${s.malicious}/${total} engines flagged this as malicious. Engines include: ${engineDetails || "None"}. Overall detection stats indicate ${s.malicious} malicious and ${s.suspicious} suspicious findings.`,
            source: "VirusTotal"
          });
        } else {
          limitations.push("VirusTotal unavailable or no record found");
        }
      }

      // 3. ABUSEIPDB & IP Analysis
      if (detected === "IP") {
        const isPrivate = isPrivateIP(normalizedInput);
        
        if (isPrivate) {
          calculatedVerdict = "LEGIT_SIGNAL";
          calculatedPercentage = 100;
          baseSignals.push({
            name: "Private/Internal IP Address",
            severity: "INFO",
            description: `The IP ${normalizedInput} belongs to a private, reserved, or local network range. It is not publicly routable and cannot be checked against external reputation databases.`,
            source: "IP Parser"
          });
          contextParts.push(`[SOURCE: IP Parser] Type=Private/Internal, IP=${normalizedInput}`);
        } else {
          const [abuseData, vtData] = await Promise.all([
            callAbuseIPDB(normalizedInput),
            callVirusTotal('ip', normalizedInput)
          ]);

          let abuseVerdict = "LEGIT_SIGNAL";
          let vtVerdict = "LEGIT_SIGNAL";
          let abuseScore = 0;

          if (abuseData) {
            sourcesUsed.push("AbuseIPDB");
            abuseScore = abuseData.abuseConfidenceScore || 0;
            const reports = abuseData.totalReports || 0;
            
            contextParts.push(`[SOURCE: AbuseIPDB] ConfidenceScore=${abuseScore}%, TotalReports=${reports}, Country=${abuseData.countryCode}, ISP=${abuseData.isp}, Domain=${abuseData.domain}, Usage=${abuseData.usageType}, Whitelisted=${abuseData.isWhitelisted}, Tor=${abuseData.isTor}, LastReported=${abuseData.lastReportedAt || "Never"}`);

            if (abuseScore >= 50) abuseVerdict = "MALICIOUS_THREAT";
            else if (abuseScore >= 10) abuseVerdict = "SUSPICIOUS_ACTIVITY";

            baseSignals.push({
              name: "AbuseIPDB Confidence Score",
              severity: abuseScore >= 50 ? "CRITICAL" : (abuseScore >= 10 ? "WARNING" : "INFO"),
              description: `This IP has a ${abuseScore}% abuse confidence score based on ${reports} reports. ISP: ${abuseData.isp || "Unknown"}, Usage: ${abuseData.usageType || "Unknown"}.`,
              source: "AbuseIPDB"
            });

            if (reports > 0) {
              baseSignals.push({
                name: "IP Report History",
                severity: reports > 100 ? "CRITICAL" : (reports > 5 ? "WARNING" : "INFO"),
                description: `IP has been reported ${reports} times for abusive behavior (hacking, spam, etc.). Last activity reported: ${abuseData.lastReportedAt || "N/A"}.`,
                source: "AbuseIPDB"
              });
            }
          }

          if (vtData && vtData.last_analysis_stats) {
            sourcesUsed.push("VirusTotal");
            const s = vtData.last_analysis_stats;
            const total = s.malicious + s.suspicious + s.harmless + s.undetected;
            
            contextParts.push(`[SOURCE: VirusTotal IP] Malicious=${s.malicious}, Suspicious=${s.suspicious}, Harmless=${s.harmless}, Undetected=${s.undetected}, Reputation=${vtData.reputation || 0}, ASN=${vtData.asn || "Unknown"}, Country=${vtData.country || "Unknown"}`);

            if (s.malicious >= 3) vtVerdict = "MALICIOUS_THREAT";
            else if (s.malicious > 0 || s.suspicious > 0) vtVerdict = "SUSPICIOUS_ACTIVITY";

            baseSignals.push({
              name: "VirusTotal IP Reputation",
              severity: s.malicious >= 3 ? "CRITICAL" : (s.malicious > 0 ? "WARNING" : "INFO"),
              description: `Malicious detections: ${s.malicious}/${total} engines. Community reputation score: ${vtData.reputation || 0}. ASN: ${vtData.asn || "N/A"}, Owner: ${vtData.as_owner || "N/A"}.`,
              source: "VirusTotal"
            });
            
            if (vtData.country) {
              baseSignals.push({
                name: "Geographic Origin",
                severity: "INFO",
                description: `IP address originated from ${vtData.country}. This metadata is used for context but does not inherently imply risk.`,
                source: "VirusTotal"
              });
            }
          }

          // Merge Logic
          if (abuseVerdict === "MALICIOUS_THREAT" || vtVerdict === "MALICIOUS_THREAT") {
            calculatedVerdict = "MALICIOUS_THREAT";
          } else if (abuseVerdict === "SUSPICIOUS_ACTIVITY" || vtVerdict === "SUSPICIOUS_ACTIVITY") {
            calculatedVerdict = "SUSPICIOUS_ACTIVITY";
          } else {
            calculatedVerdict = "LEGIT_SIGNAL";
          }

          // Disagreement Check
          if (abuseVerdict !== vtVerdict && abuseData && vtData) {
            baseSignals.push({
              name: "Threat Intelligence Disagreement",
              severity: "INFO",
              description: `AbuseIPDB rated this as ${abuseVerdict} while VirusTotal rated it as ${vtVerdict}. This may indicate a newly neutralized threat or varying detection methodologies.`,
              source: "Analysis Engine"
            });
          }

          // Score Calculation
          const vtScoreImpact = vtData?.last_analysis_stats?.malicious ? (vtData.last_analysis_stats.malicious / (vtData.last_analysis_stats.malicious + vtData.last_analysis_stats.harmless + 1)) * 100 : 0;
          calculatedPercentage = Math.round(100 - Math.max(abuseScore, vtScoreImpact));
        }
      }

      // 4. RDAP
      if (detected === "DOMAIN" || detected === "WEBSITE") {
        const domainToLook = detected === "WEBSITE" ? normalizedInput.replace(/^https?:\/\//, "").split("/")[0] : normalizedInput;
        const r = await callRDAP(domainToLook);
        if (r) {
          sourcesUsed.push("RDAP/WHOIS");
          const events = r.events || [];
          const reg = events.find((e: any) => e.eventAction === 'registration');
          const lastExp = events.find((e: any) => e.eventAction === 'expiration');
          
          let ageInfo = "Unknown age";
          if (reg?.eventDate) {
            const ageDays = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / (1000 * 60 * 60 * 24));
            ageInfo = `${ageDays} days old`;
            contextParts.push(`[SOURCE: RDAP] RegistrationDate=${reg.eventDate}, ExpirationDate=${lastExp?.eventDate || "Unknown"}, Registrar=${r.port43 || "Unknown"}, AgeDays=${ageDays}`);
            
            if (ageDays < 7) {
              if (calculatedVerdict === "LEGIT_SIGNAL") calculatedVerdict = "SUSPICIOUS_ACTIVITY";
              calculatedPercentage = Math.min(calculatedPercentage, 20);
              baseSignals.push({
                name: "Extreme Domain Youth",
                severity: "CRITICAL",
                description: `Domain was registered extremely recently (${ageDays} days ago). This is a top indicator for phishing and rapid-deployment scam operations.`,
                source: "WHOIS/RDAP"
              });
            } else if (ageDays < 30) {
              if (calculatedVerdict === "LEGIT_SIGNAL") calculatedVerdict = "SUSPICIOUS_ACTIVITY";
              calculatedPercentage = Math.min(calculatedPercentage, 50);
              baseSignals.push({
                name: "Young Domain Risk",
                severity: "WARNING",
                description: `Domain is under 30 days old. New domains lack long-term reputation and are frequently used in short-lived malicious campaigns.`,
                source: "WHOIS/RDAP"
              });
            }
          } else {
            contextParts.push(`[SOURCE: RDAP] Registrar=${r.port43 || "Unknown"}, EventsCount=${events.length}`);
          }
        } else {
          limitations.push("RDAP/WHOIS lookup unavailable or domain not found");
        }
      }

      // 5. EML Forensic
      if (detected === "EML") {
        sourcesUsed.push("EML Parser");
        const lines = normalizedInput.split("\n");
        const getHeader = (key: string) => lines.find(l => l.toLowerCase().startsWith(`${key.toLowerCase()}:`))?.substring(key.length + 1).trim() || "";
        
        const fromRaw = getHeader("From");
        const returnPathRaw = getHeader("Return-Path");
        const replyToRaw = getHeader("Reply-To");
        const xMailer = getHeader("X-Mailer") || getHeader("User-Agent");
        const arcResults = getHeader("ARC-Authentication-Results") || getHeader("Authentication-Results");
        const receivedHops = lines.filter(l => l.toLowerCase().startsWith("received:")).length;
        const listUnsubscribe = getHeader("List-Unsubscribe");
        
        // Anti-spam headers
        const sclHeader = getHeader("X-MS-Exchange-Organization-SCL") || getHeader("X-Forefront-Antispam-Report");
        let scl = -1;
        if (sclHeader) {
          const match = sclHeader.match(/SCL:?(\d+)/i);
          if (match) scl = parseInt(match[1]);
        }

        const fromEmail = extractEmailAddress(fromRaw);
        const rpEmail = extractEmailAddress(returnPathRaw);
        const replyEmail = extractEmailAddress(replyToRaw);

        const fromDomain = getEmailDomain(fromEmail);
        const rpDomain = getEmailDomain(rpEmail);
        const replyDomain = getEmailDomain(replyEmail);

        const fromOrg = getOrgDomain(fromDomain);
        const rpOrg = getOrgDomain(rpDomain);
        const replyOrg = getOrgDomain(replyDomain);

        const authSummary = {
          spf: (arcResults.match(/spf=(\w+)/i)?.[1] || "unknown").toLowerCase(),
          dkim: (arcResults.match(/dkim=(\w+)/i)?.[1] || "unknown").toLowerCase(),
          dmarc: (arcResults.match(/dmarc=(\w+)/i)?.[1] || "unknown").toLowerCase(),
          compauth: (arcResults.match(/compauth=(\w+)/i)?.[1] || "unknown").toLowerCase()
        };

        // SCORING ENGINE
        let score = 70;
        
        // Positive Signals
        if (authSummary.spf === "pass") score += 10;
        if (authSummary.dkim === "pass") score += 10;
        if (authSummary.dmarc === "pass") score += 10;
        if (authSummary.compauth === "pass") score += 5;
        if (scl >= 0 && scl <= 1) score += 5;
        if (listUnsubscribe) score += 5;
        if (fromOrg && rpOrg && fromOrg === rpOrg) score += 5;

        // Negative Signals
        if (authSummary.spf === "fail") {
          score -= 25;
          baseSignals.push({ name: "SPF Authentication Failure", severity: "CRITICAL", description: "The sending server is NOT authorized by the domain's SPF record. High indicator of spoofing.", source: "EML Parser" });
        }
        if (authSummary.dkim === "fail") {
          score -= 25;
          baseSignals.push({ name: "DKIM Signature Invalid", severity: "WARNING", description: "The email's digital signature failed verification, meaning the content may have been tampered with or modified in transit.", source: "EML Parser" });
        }
        if (authSummary.dmarc === "fail") {
          score -= 30;
          baseSignals.push({ name: "DMARC Policy Rejection", severity: "CRITICAL", description: "The email failed the domain's DMARC policy. This indicates that the sender identity could not be verified by SPF or DKIM.", source: "EML Parser" });
        }
        if (authSummary.compauth === "fail") score -= 20;
        
        if (replyDomain && fromOrg && replyOrg !== fromOrg) {
          score -= 15;
          baseSignals.push({ name: "Unrelated Reply-To Domain", severity: "WARNING", description: `The Reply-To address (${replyEmail}) is unrelated to the sender's organizational domain (${fromOrg}).`, source: "EML Parser" });
        }
        if (rpDomain && fromOrg && rpOrg !== fromOrg) {
          score -= 15;
          baseSignals.push({ name: "Return-Path Mismatch", severity: "WARNING", description: `The bounce/return-path domain (${rpDomain}) does not align with the Sender's organizational domain (${fromDomain}).`, source: "EML Parser" });
        }

        // Add INFO signals for transparency
        if (listUnsubscribe) {
          baseSignals.push({ name: "Marketing Email (Unsubscribe Available)", severity: "INFO", description: "Legitimate bulk email identifier found (List-Unsubscribe). This suggests a commercial or marketing source.", source: "EML Parser" });
        }
        if (scl >= 0) {
          baseSignals.push({ name: "Microsoft Spam Confidence Level", severity: "INFO", description: `Microsoft SCL is ${scl} (Values 0-1 are highly legitimate, 5-9 are likely spam).`, source: "EML Parser" });
        }

        calculatedPercentage = Math.max(0, Math.min(100, score));
        
        if (calculatedPercentage >= 80) calculatedVerdict = "LEGIT_SIGNAL";
        else if (calculatedPercentage < 50) calculatedVerdict = "SUSPICIOUS_ACTIVITY";
        else {
          calculatedVerdict = baseSignals.length > 0 ? "SUSPICIOUS_ACTIVITY" : "LEGIT_SIGNAL";
        }

        contextParts.push(`[SOURCE: EML Parser] From=${fromEmail}, RP=${rpEmail}, Reply=${replyEmail}, Alignment=${fromOrg === rpOrg ? "YES" : "NO"}, SPF=${authSummary.spf}, DKIM=${authSummary.dkim}, DMARC=${authSummary.dmarc}, SCL=${scl}, ListUnsub=${!!listUnsubscribe}`);
      }

      const realContext = contextParts.filter(Boolean).sort().join("\n") || "No detailed API data available. Analysis relies on observable technical patterns.";
      
      const prompt = `Calculated Primary Factors:
Recommended Verdict: ${calculatedVerdict}
Recommended Legitimacy Percentage: ${calculatedPercentage}%

REAL_CONTEXT (Extracted facts from APIs and Parsers):
${realContext}

USER_INPUT (Raw data provided by user):
${normalizedInput}

SCAN_TYPE:
${type}

SOURCES_CHECKED:
${sourcesUsed.join(", ")}

LIMITATIONS:
${limitations.join(", ")}

Task: Generate a comprehensive forensic report.
Strict Rules for Analysis:
1. Ground Truth: Use Calculated Primary Factors (Verdict/Percentage) as your ground truth. Explain WHY these were calculated.
2. EML & Marketing: Do NOT mark emails as suspicious purely for having tracking URLs, UTMs, or marketing headers (SFMC, Salesforce, etc.) if SPF/DKIM passes and domains align. Recognize these as legitimate commercial activity.
3. No Hallucinations: Do NOT invent VirusTotal counts, AbuseIPDB scores, or WHOIS dates not found in REAL_CONTEXT.
4. Signal Sourcing: Link every claim to a specific header or API result.
5. Domain Alignment: For EML, prioritize 'Organizational Domain' alignment (e.g., e.atlassian.com = atlassian.com).
6. Security Logic: If SPF/DKIM/DMARC all PASS, the email is likely legitimate unless a malicious URL is EXPLICITLY flagged by VirusTotal in the REAL_CONTEXT.
7. Detailed Names: Include specific entity names (e.g., ISP names, Domain Registrars, Network Owners, Organization names) in your descriptions if they are present in the REAL_CONTEXT. Do not use generic terms if specific ones are available.
8. No Decimals: The legitimacyPercentage must be a whole number (integer) only. Do not use decimals.`;

      const { data: rawJson, provider } = await performAnalysisWithFallback(prompt);
      const jsonMatch = rawJson.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error("AI provider returned invalid response format.");
      
      let aiResult;
      try {
        // Clean up common AI JSON artifacts before parsing (like trailing commas)
        const cleaned = jsonMatch[0].replace(/,\s*([\]}])/g, '$1');
        aiResult = JSON.parse(cleaned);
      } catch (e) {
        try {
          aiResult = JSON.parse(jsonMatch[0]);
        } catch (innerError) {
          console.error("Raw AI Output failing parse:", rawJson);
          throw new Error("AI provider returned malformed JSON.");
        }
      }

      // FINAL MERGE: Strictly enforce backend calculations
      const finalResult = {
        legitimacyPercentage: Math.round(calculatedPercentage),
        verdict: calculatedVerdict,
        executiveSummary: aiResult.executiveSummary || "Forensic analysis completed with evidence-backed results.",
        forensicSignals: [
          ...baseSignals,
          ...(aiResult.forensicSignals || []).filter((s: any) => !baseSignals.some(b => b.name === s.name))
        ],
        sourcesChecked: sourcesUsed,
        limitations: limitations,
        recommendedActions: aiResult.recommendedActions || ["Proceed with caution", "Verify sender through secondary channels"]
      };

      scanCache.set(cacheKey, { result: finalResult, expiresAt: Date.now() + CACHE_TTL_MS });
      return res.json({ success: true, data: finalResult, provider, remaining });
    } catch (err: any) {
      console.error("Analysis Error:", err);
      return res.status(500).json({ 
        error: err.message || "Internal Analysis Error",
        providerErrors: err.providerErrors 
      });
    }
  }

  return res.status(400).json({ 
    error: "Invalid action", 
    expectedActions: ["status", "analyze"],
    receivedAction: action 
  });
}


