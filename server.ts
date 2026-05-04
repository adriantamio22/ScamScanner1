import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import "dotenv/config";

async function callHIBP(email: string): Promise<any[]> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) return [];

  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: {
        "hibp-api-key": apiKey,
        "user-agent": "ScamScanner-Forensic-Lab"
      }
    });

    if (res.status === 404) return [];
    if (!res.ok) return [];

    return await res.json() as any[];
  } catch (err) {
    console.error("HIBP Error:", err);
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
`;

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

async function callGemini(userMessage: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error("GEMINI_API_KEY is not configured");

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

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/gemini", async (req, res) => {
    const { action, type, input } = req.body ?? {};

    if (action === "analyze") {
      try {
        let hibpContext = "";
        if (type === "MAILBOX" || type === "EMAIL") {
          try {
            const breaches = await callHIBP(input);
            if (breaches.length > 0) {
              hibpContext = `\n[FORENSIC_DATA: HIBP_DATA_LEAK_DETECTED]\nThis identity has been compromised in ${breaches.length} breaches: ${breaches.slice(0, 5).map((b: any) => b.Name).join(", ")}${breaches.length > 5 ? " and others" : ""}.`;
            } else {
              hibpContext = `\n[FORENSIC_DATA: HIBP_CLEAN]\nNo known breaches found in public HIBP database for this identity.`;
            }
          } catch (e) {
            console.warn("HIBP check failed", e);
          }
        }

        const prompt = `Analyze this ${type} input: ${input}. Perform a deep forensic simulation.${hibpContext}`;
        
        let result = "";
        const errors: string[] = [];

        // Try Puter if configured
        if (process.env.PUTER_API_KEY) {
          try {
            result = await callPuterAI(prompt);
          } catch (err: any) {
            console.warn("Puter AI failed, attempting fallback:", err.message);
            errors.push(`Puter: ${err.message}`);
          }
        }

        // Fallback to Gemini if Puter failed or wasn't configured
        if (!result && process.env.GEMINI_API_KEY) {
          try {
            result = await callGemini(prompt);
          } catch (err: any) {
            console.warn("Gemini AI failed:", err.message);
            errors.push(`Gemini: ${err.message}`);
          }
        }

        if (!result) {
          throw new Error(`AI_PROVIDER_FAILURE: ${errors.join(" | ") || "No providers configured"}`);
        }

        let cleanJson = result.trim();
        if (cleanJson.includes("```json")) {
          cleanJson = cleanJson.split("```json")[1].split("```")[0].trim();
        } else if (cleanJson.includes("```")) {
          cleanJson = cleanJson.split("```")[1].split("```")[0].trim();
        }

        const data = JSON.parse(cleanJson);
        return res.json({ success: true, data });
      } catch (err: any) {
        console.error("Analysis Error:", err);
        return res.status(500).json({ error: err.message || "Analysis failed" });
      }
    }

    if (action === "hibp") {
      try {
        const breaches = await callHIBP(input);
        let hibpContext = "";
        if (breaches.length > 0) {
          hibpContext = `\n[FORENSIC_DATA: HIBP_DATA_LEAK_DETECTED]\nThis identity has been compromised in ${breaches.length} breaches: ${breaches.slice(0, 5).map((b: any) => b.Name).join(", ")}${breaches.length > 5 ? " and others" : ""}.`;
        } else {
          hibpContext = `\n[FORENSIC_DATA: HIBP_CLEAN]\nNo known breaches found in public HIBP database for this identity.`;
        }
        return res.json({ context: hibpContext });
      } catch (err: any) {
        console.error("HIBP Error:", err);
        return res.status(500).json({ error: "HIBP check failed" });
      }
    }

    if (action === "status") {
      return res.json({ ok: true, status: "OPERATIONAL" });
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
