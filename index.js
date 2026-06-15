"use strict";

const http = require("http");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 8080);
const ONLINE_PRO_TOKEN = process.env.ONLINE_PRO_TOKEN || "";
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || "";
const SAFE_BROWSING_API_KEY = process.env.SAFE_BROWSING_API_KEY || "";

const TRUSTED_PACKAGES = new Set([
  "com.android.vending",
  "com.google.android.gms",
  "com.google.android.gsf",
  "com.android.packageinstaller"
]);

function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 120000) {
        reject(new Error("payload_too_large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch (error) {
        reject(new Error("bad_json"));
      }
    });
    req.on("error", reject);
  });
}

function cleanDomain(domain) {
  return String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0];
}

function localReputation(input) {
  const domains = Array.isArray(input.domains) ? input.domains.map(cleanDomain).filter(Boolean) : [];
  const trackers = Array.isArray(input.trackers) ? input.trackers : [];
  const protectSignals = Array.isArray(input.protectSignals) ? input.protectSignals : [];
  const packageName = String(input.packageName || "");

  let score = Number(input.localScore || 0);
  const notes = [];

  if (TRUSTED_PACKAGES.has(packageName)) {
    score = Math.min(score, 25);
    notes.push("Package Google/Android attendibile: rischio locale limitato.");
  }
  if (domains.some(d => d.endsWith(".top") || d.endsWith(".xyz") || d.endsWith(".ru"))) {
    score += 8;
    notes.push("Dominio con TLD da verificare.");
  }
  if (domains.length > 5) {
    score += 5;
    notes.push("Molti domini leggibili nell'APK.");
  }
  if (trackers.length > 3) {
    score += 8;
    notes.push("Diversi SDK tracker rilevati.");
  }
  if (protectSignals.length > 0) {
    score += 10;
    notes.push("Segnali tecnici locali da verificare.");
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, notes, domains };
}

async function checkVirusTotalDomain(domain) {
  if (!VIRUSTOTAL_API_KEY || !domain) return null;
  const response = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    headers: { "x-apikey": VIRUSTOTAL_API_KEY }
  });
  if (!response.ok) return null;
  const json = await response.json();
  const stats = json?.data?.attributes?.last_analysis_stats || {};
  return {
    domain,
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0)
  };
}

async function checkSafeBrowsing(domains) {
  if (!SAFE_BROWSING_API_KEY || domains.length === 0) return [];
  const entries = domains.slice(0, 20).map(domain => ({ url: `http://${domain}/` }));
  const body = {
    client: { clientId: "privacy-radar", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: entries
    }
  };
  const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) return [];
  const json = await response.json();
  return Array.isArray(json.matches) ? json.matches : [];
}

function verdictFor(score) {
  if (score < 35) return "rischio basso";
  if (score < 68) return "rischio medio";
  return "rischio alto";
}

async function handleOnlineCheck(req, res) {
  if (ONLINE_PRO_TOKEN) {
    const auth = req.headers.authorization || "";
    if (auth !== `Bearer ${ONLINE_PRO_TOKEN}`) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
  }

  const input = await readJson(req);
  const reputation = localReputation(input);
  let score = reputation.score;
  const notes = [...reputation.notes];
  const providers = ["Privacy Radar server"];

  const vtResults = [];
  for (const domain of reputation.domains.slice(0, 5)) {
    try {
      const result = await checkVirusTotalDomain(domain);
      if (result) vtResults.push(result);
    } catch (_) {
      notes.push("VirusTotal non disponibile per alcuni domini.");
    }
  }

  const vtBad = vtResults.reduce((sum, item) => sum + item.malicious + item.suspicious, 0);
  if (vtResults.length > 0) {
    providers.push("VirusTotal");
    if (vtBad > 0) {
      score += Math.min(25, vtBad * 8);
      notes.push(`VirusTotal segnala ${vtBad} rilevazioni su domini.`);
    } else {
      notes.push("VirusTotal non segnala domini malevoli tra quelli controllati.");
    }
  }

  try {
    const sbMatches = await checkSafeBrowsing(reputation.domains);
    if (SAFE_BROWSING_API_KEY) providers.push("Google Safe Browsing");
    if (sbMatches.length > 0) {
      score += 25;
      notes.push(`Safe Browsing segnala ${sbMatches.length} match.`);
    }
  } catch (_) {
    notes.push("Safe Browsing non disponibile.");
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  sendJson(res, 200, {
    provider: providers.join(", "),
    verdict: verdictFor(score),
    score,
    notes: notes.length ? notes.join(" ") : "Nessun segnale online forte.",
    checkedAt: new Date().toISOString()
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, { ok: true, service: "privacy-radar-online-pro" });
      return;
    }
    if (req.method === "POST" && url.pathname === "/privacy-radar/check") {
      await handleOnlineCheck(req, res);
      return;
    }
    sendJson(res, 404, { error: "not_found" });
  } catch (error) {
    sendJson(res, 400, { error: error.message || "bad_request" });
  }
});

server.listen(PORT, () => {
  console.log(`Privacy Radar Online Pro listening on ${PORT}`);
});
