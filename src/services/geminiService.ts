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
  // Delegate both data gathering AND AI analysis to the server
  // This allows the server to manage fallbacks between Gemini, Groq, and OpenRouter securely
  const res = await fetch("/api/gemini", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "analyze", type, input })
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || `Analysis failed with status ${res.status}`);
  }

  const { result } = await res.json();

  return {
    id: Math.random().toString(36).substring(7),
    type,
    input,
    ...result,
    timestamp: Date.now()
  };
}
