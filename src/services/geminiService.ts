import { ScanResult, ToolType } from "../types";

export async function checkApiStatus(): Promise<{ ok: boolean; status: string }> {
  try {
    const res = await fetch("/api/gemini", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "status" }),
    });
    return await res.json();
  } catch {
    return { ok: false, status: "API_ERROR" };
  }
}

export async function performForensicAnalysis(type: ToolType, input: string): Promise<ScanResult> {
  let hibpContext = "";
  if (type === "EMAIL" || type === "LOOKUP") {
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
    } catch {
      // proceed without HIBP data
    }
  }

  const res = await fetch("/api/gemini", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "analyze", type, input: `${input}${hibpContext}` }),
  });

  if (!res.ok) {
    const err = await res.json();
    if (err.error === "RATE_LIMITED") throw new Error(`RATE_LIMITED: ${err.message}`);
    throw new Error(err.error || "Analysis failed");
  }

  const { data } = await res.json();
  return {
    ...data,
    userId: "anonymous",
    type,
    input,
    createdAt: Date.now(),
    id: Math.random().toString(36).substring(2, 15),
  };
}
