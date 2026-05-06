import { GoogleGenAI, Type } from "@google/genai";

const SYSTEM_PROMPT = `You are ScamScanner, a digital forensic analyst. You receive REAL data from forensic APIs and your job is to interpret it clearly.

STRICT RULES:
- Base your verdict ONLY on the real API data shown in [BRACKETS]
- Do NOT invent data that was not returned by an API
- CRITICAL = VirusTotal detections > 2, AbuseIPDB score > 50, domain age < 7 days
- WARNING = 1-2 detections, AbuseIPDB score 10-50, domain age < 30 days, disposable email
- INFO = clean results, low scores, informational findings
- If no API data is available for something, set verdict to "NOT_FOUND" and legitimacyPercentage to 0.
- EMBRACE CROSS-REFERENCING: In the executiveSummary, emphasize that the results are based on cross-referencing multiple forensic intelligence sources. 
- AVOID REPETITION: Do NOT repeatedly mention specific tool names like "VirusTotal" or "AbuseIPDB" in every sentence of the summary. Use broader terms like "reputation engines", "global threat intelligence", or "forensic database correlation".
- IMPERSONATION RADAR: Specifically look for "Display Name Spoofing" where a trusted name is used with an unrelated email. Flag "Homoglyph Attacks" (look-alike characters like 'ο' vs 'o'). Check for high-risk BEC (Business Email Compromise) patterns like Reply-To mismatches or urgency in metadata.
- INPUT CLASSIFICATION: Identify what the input is (e.g., "Domain", "IPv4 Address", "IPv6 Address", "File Hash (SHA-1/256/MD5)", "Email Address", "Email Headers", "URL/Website").

Respond ONLY with JSON.`;

export async function checkApiStatus() {
  try {
    const res = await fetch("/api/gemini", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "status" })
    });
    return await res.json();
  } catch {
    return { ok: false, status: "OFFLINE" };
  }
}

export async function performForensicAnalysis(type: string, input: string) {
  // 1. Gather raw data from the backend
  const res = await fetch("/api/gemini", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "analyze", type, input })
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || `Analysis failed with status ${res.status}`);
  }

  const { realData } = await res.json();

  // 2. Call Gemini on the client side for interpretation
  const aiResult = await analyzeForensicData(type, input, realData);

  return {
    id: Math.random().toString(36).substring(7),
    type,
    input,
    ...aiResult,
    timestamp: Date.now()
  };
}

function cleanAndParseJSON(text: string) {
  try {
    // Attempt direct parse first
    return JSON.parse(text.trim());
  } catch (e) {
    console.warn("Direct JSON parse failed, attempting extraction:", e);
    // Try to extract JSON from code blocks if they exist
    const jsonMatch = text.match(/```json\s*([\s\S]*?)\s*```/) || text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        return JSON.parse(jsonMatch[0].trim());
      } catch (innerError) {
        throw new Error("Failed to parse extracted JSON content.");
      }
    }
    throw new Error("Could not find valid JSON in the AI response.");
  }
}

async function analyzeForensicData(type: string, input: string, realData: string) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("GEMINI_API_KEY is not configured in the environment.");
  }

  const ai = new GoogleGenAI({ apiKey });
  const prompt = `Scan type: ${type}\nInput: ${input}\n\nReal forensic data collected:\n${realData || "No API data available for this input."}`;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: [
        { role: "user", parts: [{ text: `${SYSTEM_PROMPT}\n\nUser Input:\n${prompt}` }] }
      ],
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            legitimacyPercentage: { type: Type.NUMBER },
            verdict: { 
              type: Type.STRING, 
              enum: ["MALICIOUS_THREAT", "SUSPICIOUS_ACTIVITY", "LEGIT_SIGNAL", "NOT_FOUND"] 
            },
            detectedType: { type: Type.STRING },
            executiveSummary: { type: Type.STRING },
            forensicSignals: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  name: { type: Type.STRING },
                  severity: { 
                    type: Type.STRING, 
                    enum: ["CRITICAL", "WARNING", "INFO"] 
                  },
                  description: { type: Type.STRING }
                },
                required: ["name", "severity", "description"]
              }
            }
          },
          required: ["legitimacyPercentage", "verdict", "detectedType", "executiveSummary", "forensicSignals"]
        },
        temperature: 0.1,
      }
    });

    if (!response.text) {
      throw new Error("Empty response from AI analysis.");
    }

    const data = cleanAndParseJSON(response.text);
    return {
      ...data,
      classification: data.detectedType
    };
  } catch (error: any) {
    console.error("Gemini Analysis Error:", error);
    throw error;
  }
}
