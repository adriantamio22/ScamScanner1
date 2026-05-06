import { ScanResult, ToolType } from "../types";

export async function checkApiStatus(): Promise<{ ok: boolean; status: string; provider?: string; model?: string; message?: string }> {
  try {
    const res = await fetch("/api/gemini", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "status" }),
    });
    return await res.json();
  } catch (err: any) {
    return { ok: false, status: "API_ERROR", message: err.message };
  }
}

export async function performForensicAnalysis(type: ToolType, input: string): Promise<ScanResult> {
  const res = await fetch("/api/gemini", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "analyze", type, input }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || err.error || "Analysis failed");
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
