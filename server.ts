import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { GoogleGenAI, Type } from "@google/genai";
import "dotenv/config";

const KEYS = [
  process.env.GEMINI_API_KEY_1,
  process.env.GEMINI_API_KEY_2,
  process.env.GEMINI_API_KEY_3,
  process.env.GEMINI_API_KEY_4,
  process.env.GEMINI_API_KEY_5,
].filter((k): k is string => Boolean(k));

const SYSTEM_PROMPT = `You are the core engine of ScamScanner, a "Bento Grid" Digital Forensic Lab.
Your task is to analyze inputs for three specialized tools:
1. Mailbox Checker: Analyzes email safety, MX/SPF/DMARC records, and malicious attachments/links.
2. Email Address Verifier: Checks syntax, mailbox existence, disposable/burner status, and spoofing reputation.
3. IP Analysis: Detects VPN/Proxy/Tor exit nodes, abuse confidence scores, and geolocation/ISP data.
4. Website Checker: Emulates VirusTotal/Google Safe Browsing. Analyzes URL safety, SSL certificates, phishing patterns, and domain age/reputation.
5. EML Investigator: Analyzes raw email (.eml) source code. Extracts headers, identifies spoofed "From" addresses, analyzes "Reply-To" mismatches, and evaluates embedded link/attachment risk.

For any input, you must provide:
- A Legitimacy Percentage (0-100%).
- A Verdict: MALICIOUS_THREAT, SUSPICIOUS_ACTIVITY, or LEGIT_SIGNAL.
- An Executive Summary (concise forensic overview).
- A list of Forensic Signals (Evidence bits with severity: CRITICAL, WARNING, INFO).

Use your vast intelligence to simulate real-world forensic tool outputs. If an input is clearly a test or placeholder, still provide a realistic, professional response.`;

const RESPONSE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    legitimacyPercentage: { type: Type.NUMBER },
    verdict: { type: Type.STRING, enum: ["MALICIOUS_THREAT", "SUSPICIOUS_ACTIVITY", "LEGIT_SIGNAL"] },
    executiveSummary: { type: Type.STRING },
    forensicSignals: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          name: { type: Type.STRING },
          severity: { type: Type.STRING, enum: ["CRITICAL", "WARNING", "INFO"] },
          description: { type: Type.STRING },
        },
        required: ["name", "severity", "description"],
      },
    },
  },
  required: ["legitimacyPercentage", "verdict", "executiveSummary", "forensicSignals"],
};

function isQuotaError(err: any): boolean {
  return (
    err.message?.includes("429") ||
    err.message?.includes("RESOURCE_EXHAUSTED") ||
    err.message?.includes("credits are depleted")
  );
}

// In-memory rate limiting
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour

function checkRateLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, remaining: RATE_LIMIT_COUNT - 1 };
  }

  if (record.count >= RATE_LIMIT_COUNT) {
    return { allowed: false, remaining: 0 };
  }

  record.count += 1;
  return { allowed: true, remaining: RATE_LIMIT_COUNT - record.count };
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/gemini", async (req, res) => {
    const { action, type, input } = req.body ?? {};

    if (!KEYS.length) {
      return res.status(500).json({ error: "No API keys configured on server" });
    }

    // Get client IP for rate limiting
    const ip = req.ip || "anonymous";
    const { allowed } = checkRateLimit(ip as string);

    if (action === "analyze" && !allowed) {
      return res.status(429).json({ 
        error: "RATE_LIMIT_EXHAUSTED", 
        message: "You have reached the limit of 5 scans per hour. Please wait before trying again." 
      });
    }

    if (action === "status") {
      for (const key of KEYS) {
        try {
          const ai = new GoogleGenAI({ apiKey: key });
          await ai.models.generateContent({
            model: "gemini-3-flash-preview",
            contents: [{ role: "user", parts: [{ text: "hi" }] }],
            config: { maxOutputTokens: 1 },
          });
          return res.json({ ok: true, status: "OPERATIONAL" });
        } catch (err: any) {
          if (isQuotaError(err)) continue;
          return res.json({ ok: false, status: "API_ERROR" });
        }
      }
      return res.json({ ok: false, status: "QUOTA_EXHAUSTED" });
    }

    if (action === "analyze") {
      for (const key of KEYS) {
        try {
          const ai = new GoogleGenAI({ apiKey: key });
          const response = await ai.models.generateContent({
            model: "gemini-3-flash-preview",
            contents: `Analyze this ${type} input: ${input}. Input content might be raw email headers/body, an IP address, a domain, or an email address. Perform a deep forensic simulation.`,
            config: {
              systemInstruction: SYSTEM_PROMPT,
              responseMimeType: "application/json",
              responseSchema: RESPONSE_SCHEMA,
            },
          });
          const rawJson = response.text?.trim();
          if (!rawJson) throw new Error("Empty response from intelligence engine.");
          return res.json({ success: true, data: JSON.parse(rawJson) });
        } catch (err: any) {
          if (isQuotaError(err)) continue;
          console.error("Gemini Error:", err);
        }
      }
      return res.status(429).json({ error: "QUOTA_EXHAUSTED" });
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
