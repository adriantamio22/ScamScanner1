import { ScanResult, ToolType } from "../types";
import { GoogleGenAI } from "@google/genai";

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

export async function checkApiStatus(): Promise<{ ok: boolean; status: string; info?: string; authStatus?: any }> {
  try {
    const res = await fetch("/api/gemini", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "status" }),
    });
    return await res.json();
  } catch {
    return { ok: false, status: "API_ERROR", info: "Portal connection failed." };
  }
}

async function callFrontendGemini(prompt: string): Promise<any> {
    const apiKey = (process.env as any).GEMINI_API_KEY;
    if (!apiKey) throw new Error("No Gemini API key found on frontend.");
    
    const ai = new GoogleGenAI({ apiKey });
    const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prompt,
        config: {
            systemInstruction: SYSTEM_PROMPT,
            responseMimeType: "application/json"
        }
    });

    if (!response.text) throw new Error("Gemini returned empty response.");
    return JSON.parse(response.text.trim());
}

async function callBackendFallback(message: string): Promise<any> {
    const res = await fetch("/api/gemini", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "analyze-fallback", message }),
    });
    
    if (!res.ok) throw new Error("Fallback AI also failed.");
    const { data } = await res.json();
    return data;
}

export async function performForensicAnalysis(type: ToolType, input: string): Promise<ScanResult> {
  const res = await fetch("/api/gemini", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "forensics", type, input }),
  });

  if (!res.ok) {
    const err = await res.json();
    if (err.error === "RATE_LIMITED") throw new Error(`RATE_LIMITED: ${err.message}`);
    throw new Error(err.error || "Analysis failed");
  }

  const { realData } = await res.json();
  const prompt = `Scan type: ${type}\nInput: ${input}\n\nReal forensic data collected:\n${realData || "No API data available for this input."}`;
  
  let finalData;
  try {
    // Primary: Frontend Gemini (Compliant & Proxy-optimized)
    finalData = await callFrontendGemini(prompt);
  } catch (err: any) {
    console.warn("Frontend Gemini failed, trying backend fallback...", err.message);
    // Secondary: Backend Fallback (Groq/OpenRouter)
    finalData = await callBackendFallback(prompt);
  }

  return {
    ...finalData,
    userId: "anonymous",
    type,
    input,
    createdAt: Date.now(),
    id: Math.random().toString(36).substring(2, 15),
  };
}
