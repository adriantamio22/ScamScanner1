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

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/gemini", async (req, res) => {
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
