// Esempio server proxy Online Pro.
// In produzione mettilo dietro HTTPS e conserva qui le chiavi API, mai nell'APK.
const http = require("http");

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/privacy-radar/check") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }

  let body = "";
  req.on("data", chunk => {
    body += chunk;
    if (body.length > 100000) req.destroy();
  });

  req.on("end", async () => {
    try {
      const input = JSON.parse(body || "{}");
      const domains = Array.isArray(input.domains) ? input.domains : [];
      const trackers = Array.isArray(input.trackers) ? input.trackers : [];
      const protectSignals = Array.isArray(input.protectSignals) ? input.protectSignals : [];

      let score = Number(input.localScore || 0);
      if (domains.length > 3) score += 6;
      if (trackers.length > 2) score += 8;
      if (protectSignals.length > 0) score += 10;
      score = Math.max(0, Math.min(100, score));

      const verdict = score < 35 ? "rischio basso" : score < 68 ? "rischio medio" : "rischio alto";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        provider: "Privacy Radar proxy demo",
        verdict,
        score,
        notes: "Demo locale. Collega qui VirusTotal e Google Safe Browsing con chiavi lato server."
      }));
    } catch (error) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "bad_request" }));
    }
  });
});

server.listen(8080, () => {
  console.log("Privacy Radar Online Pro demo: http://localhost:8080/privacy-radar/check");
});
