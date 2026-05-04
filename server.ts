import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import "dotenv/config";

const RATE_LIMIT = 5;
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
    return await res.json() as any[];
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
1. Domain Lookup: Comprehensive domain and URL intelligence. Performs deep checks on safety, DNS records (MX/SPF/DMARC/BIMI), domain age, SSL certificate chain, and reputation. Imagine a fusion of VirusTotal and MXToolbox.
2. Email Address Verifier: Deep verification of email identities. Checks syntax, mailbox existence, disposable/burner status, and reputation.
3. IP Analysis: Forensic IP investigation. Detections for VPN, Proxy, Tor exit nodes, data center IPs, abuse confidence scores, and geolocation.
4. Website Checker: In-depth URL and content scanning for phishing, malware, and deceptive redirection patterns.
5. EML Investigator: Advanced behavioral analysis of raw email sources (.eml). Mimics Abnormal Security by detecting identity deception, typosquatting (homoglyph attacks), suspicious structural anomalies, and business email compromise (BEC) signals.

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

  const data = await res.json() as any;
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

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/gemini", async (req, res) => {
    const { action, type, input } = req.body ?? {};

    if (action === "hibp") {
      try {
        const breaches = await callHIBP(input);
        const hibpContext = breaches.length > 0
          ? `\n[HIBP: ${breaches.length} breach(es) found: ${breaches.slice(0, 5).map((b: any) => b.Name).join(", ")}${breaches.length > 5 ? " and more" : ""}]`
          : `\n[HIBP: No known breaches found]`;
        return res.json({ context: hibpContext });
      } catch (err: any) {
        console.error("HIBP Error:", err);
        return res.status(500).json({ error: "HIBP check failed" });
      }
    }

    if (action === "status") {
      try {
        await callWithFallback("hi");
        return res.json({ ok: true, status: "OPERATIONAL" });
      } catch (err: any) {
        return res.json({ ok: false, status: "API_ERROR", message: err.message });
      }
    }

    if (action === "analyze") {
      const ip = (req.headers["x-forwarded-for"] as string) || req.ip || "unknown";
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
        console.error("Analysis Error:", err);
        return res.status(500).json({ error: err.message || "Analysis failed" });
      }
    }

    return res.status(400).json({ error: "Invalid action" });
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
