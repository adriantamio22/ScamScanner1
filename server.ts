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

async function callGroq(userMessage: string): Promise<string> {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) throw new Error("GROQ_API_KEY is not configured");

  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "llama-3.3-70b-versatile",
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userMessage },
      ],
      response_format: { type: "json_object" },
      max_tokens: 1024,
      temperature: 0.3,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `Groq API error: ${res.status}`);
  }

  const data = await res.json() as any;
  return data.choices[0].message.content;
}

async function callGemini(userMessage: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY_1;
  if (!apiKey) throw new Error("Missing GEMINI_API_KEY or GROQ_API_KEY. Please configure them in your environment settings.");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: userMessage }] }],
      systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
      generationConfig: {
        responseMimeType: "application/json",
      },
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `Gemini API error: ${res.status}`);
  }

  const data = await res.json() as any;
  return data.candidates[0].content.parts[0].text;
}

async function callPuterAI(userMessage: string): Promise<string> {
  const apiKey = process.env.PUTER_API_KEY;
  if (!apiKey) throw new Error("PUTER_API_KEY is not configured");

  const res = await fetch("https://api.puter.com/v1/ai/chat", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o",
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userMessage },
      ],
      stream: false,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error?.message || `Puter API error: ${res.status}`);
  }

  const data = await res.json() as any;
  return data.message.content;
}

async function callAI(userMessage: string): Promise<string> {
  // Try Groq First
  if (process.env.GROQ_API_KEY) {
    try {
      return await callGroq(userMessage);
    } catch (err) {
      console.warn("Groq failed, falling back to Gemini:", err);
    }
  }

  // Try Gemini
  try {
    return await callGemini(userMessage);
  } catch (err) {
    console.warn("Gemini failed, falling back to Puter:", err);
  }

  // Final fallback to Puter
  return await callPuterAI(userMessage);
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/gemini", async (req, res) => {
    const { action, type, input } = req.body ?? {};

    if (action === "status") {
      try {
        await callAI("hi");
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
        const rawJson = await callAI(
          `Analyze this ${type} input: ${input}. Perform a deep forensic simulation.`
        );
        const data = JSON.parse(rawJson);
        return res.json({ success: true, data, remaining });
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
