import { GoogleGenAI, Type } from "@google/genai";
import { ScanResult, ToolType, Verdict } from "../types";

let aiInstance: GoogleGenAI | null = null;

function getAI() {
  if (!aiInstance) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY is not defined. Please add it to your environment variables.");
    }
    aiInstance = new GoogleGenAI({ apiKey });
  }
  return aiInstance;
}

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

export async function performForensicAnalysis(type: ToolType, input: string): Promise<ScanResult> {
  const model = "gemini-1.5-flash";
  
  try {
    const ai = getAI();
    
    console.log(`Starting forensic analysis for ${type}...`);
    
    const response = await ai.models.generateContent({
      model,
      contents: `Analyze this ${type} input: ${input}. 
      Input content might be raw email headers/body, an IP address, a domain, or an email address.
      Perform a deep forensic simulation.`,
      config: {
        systemInstruction: SYSTEM_PROMPT,
        responseMimeType: "application/json",
        responseSchema: {
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
                  description: { type: Type.STRING }
                },
                required: ["name", "severity", "description"]
              }
            }
          },
          required: ["legitimacyPercentage", "verdict", "executiveSummary", "forensicSignals"]
        }
      }
    });

    const rawJson = response.text?.trim();
    if (!rawJson) {
      console.error("Gemini API returned empty text property", response);
      throw new Error("Empty response from intelligence engine.");
    }
    
    const data = JSON.parse(rawJson);
    console.log("Analysis successful:", data.verdict);
    
    return {
      ...data,
      userId: "anonymous", 
      type,
      input: input.length > 100 ? input.substring(0, 100) + '...' : input, // Truncate for display in history
      createdAt: Date.now(),
      id: Math.random().toString(36).substring(2, 15)
    };
  } catch (error: any) {
    console.error("Forensic analysis failed in geminiService:", error);
    
    // Handle specific API error codes
    if (error.message?.includes("429") || error.message?.includes("RESOURCE_EXHAUSTED")) {
      throw new Error("QUOTA_EXHAUSTED: Your AI Studio credits or free-tier quota are depleted. Please check your billing at https://aistudio.google.com/");
    }

    if (error.message?.includes("API_KEY") || error.message?.includes("API key")) {
       throw new Error("SEC_AUTH_FAILURE: Gemini API Key is invalid or missing in environment.");
    }
    throw error;
  }
}
