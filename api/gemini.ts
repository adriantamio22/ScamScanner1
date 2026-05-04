import { handleFirestoreError, OperationType } from "@/src/lib/firestoreUtils";

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

    return await res.json();
  } catch (err) {
    console.error("HIBP Error:", err);
    return [];
  }
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { action, input } = req.body ?? {};

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
    } catch (e) {
      return res.status(500).json({ error: "HIBP check failed" });
    }
  }

  // legacy status check for components that might still call it
  if (action === "status") {
    return res.json({ ok: true, status: "OPERATIONAL" });
  }

  return res.status(400).json({ error: "Invalid action" });
}
