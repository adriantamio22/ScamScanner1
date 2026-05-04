import { ScanResult, ToolType } from "../types";

declare global {
  interface Window {
    puter: any;
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

export async function checkApiStatus(): Promise<{ ok: boolean; status: string }> {
  // If puter is available, we are technically operational
  if (window.puter) {
    return { ok: true, status: "OPERATIONAL (PUTER.JS)" };
  }
  return { ok: false, status: "INITIALIZING" };
}

export async function performForensicAnalysis(type: ToolType, input: string): Promise<ScanResult> {
  if (!window.puter) {
    throw new Error("PUTER_PROTOCOL_FAILURE: Forensic engine not initialized. Please refresh.");
  }

  // Get HIBP context from server if it's an email
  let hibpContext = "";
  if (type === "EMAIL" || type === "MAILBOX") {
    try {
      const res = await fetch("/api/gemini", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "hibp", input }),
      });
      if (res.ok) {
        const { context } = await res.json();
        hibpContext = context || "";
      }
    } catch (e) {
      console.warn("HIBP contextual check failed, proceeding with standard scan.");
    }
  }

  const prompt = `Analyze this ${type} input: ${input}. Perform a deep forensic simulation.${hibpContext}\n\n${SYSTEM_PROMPT}`;
  
  try {
    const response = await window.puter.ai.chat(prompt);
    // Puter.js might return a string that occasionally has markdown backticks
    let cleanJson = response.toString();
    if (cleanJson.includes("```json")) {
      cleanJson = cleanJson.split("```json")[1].split("```")[0].trim();
    } else if (cleanJson.includes("```")) {
      cleanJson = cleanJson.split("```")[1].split("```")[0].trim();
    }

    const data = JSON.parse(cleanJson);
    
    return {
      ...data,
      userId: "anonymous",
      type,
      input,
      createdAt: Date.now(),
      id: Math.random().toString(36).substring(2, 15),
    };
  } catch (err: any) {
    console.error("Puter Analysis Error:", err);
    throw new Error(`ANALYSIS_FAILED: ${err.message || "Forensic engine timeout."}`);
  }
}
