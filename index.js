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

const KNOWN_APP_PROFILES = {
  "com.nexse.mobile.bos.eurobet": {
    name: "Eurobet",
    category: "scommesse",
    trust: "app nota/riconoscibile",
    cap: 76,
    notes: [
      "App riconosciuta come scommesse: categoria sensibile per privacy, pagamenti, identita e posizione.",
      "Il rischio principale non e malware evidente, ma dati sensibili e uso responsabile dell'account."
    ]
  },
  "host.exp.exponent": {
    name: "Expo Go",
    category: "sviluppo",
    trust: "contenitore sviluppo",
    cap: 62,
    notes: [
      "Expo Go e un contenitore di sviluppo: molti domini, moduli e permessi tecnici possono essere normali.",
      "Da valutare soprattutto origine installazione e firma, non il numero grezzo di componenti."
    ]
  }
};

const CATEGORY_PROFILES = [
  {
    category: "scommesse",
    match: ["scommess", "betting", "casino", "eurobet", "goldbet", "snai", "sisal", "bet365", "poker", "bingo"],
    cap: 78,
    trust: "categoria riconosciuta: scommesse/casino",
    notes: [
      "App scommesse/casino: rischio privacy alto per pagamenti, identita, posizione e uso account.",
      "Non va marcata come malware senza segnali forti: va distinta la categoria sensibile dalla pericolosita tecnica."
    ]
  },
  {
    category: "prestiti/finanza",
    match: ["prestito", "prestiti", "loan", "credito", "finance", "bank", "trading"],
    cap: 82,
    trust: "categoria riconosciuta: finanza/prestiti",
    notes: [
      "App finanziaria/prestiti: controlla societa, licenza, contatti ufficiali e richiesta di SMS/contatti/documenti.",
      "Il rischio cresce molto se combina SMS, contatti, accessibilita o installazione esterna."
    ]
  },
  {
    category: "crypto",
    match: ["crypto", "bitcoin", "wallet", "token", "exchange", "defi"],
    cap: 84,
    trust: "categoria riconosciuta: crypto",
    notes: [
      "App crypto: categoria ad alto impatto economico, verificare sviluppatore, dominio ufficiale e recensioni recenti.",
      "Diffida di APK esterni, promesse di guadagno e permessi non coerenti."
    ]
  },
  {
    category: "vpn/sicurezza",
    match: ["vpn", "antivirus", "security", "cleaner", "booster"],
    cap: 80,
    trust: "categoria riconosciuta: VPN/sicurezza",
    notes: [
      "App VPN/sicurezza: puo vedere o filtrare molto traffico, quindi serve fiducia elevata nello sviluppatore.",
      "Permessi di accessibilita, overlay o uso in background richiedono una spiegazione molto chiara."
    ]
  },
  {
    category: "sviluppo",
    match: ["expo", "developer", "debug", "testflight", "devtools"],
    cap: 62,
    trust: "categoria riconosciuta: sviluppo/test",
    notes: [
      "App di sviluppo/test: molti moduli, domini e componenti tecnici possono essere normali.",
      "Il giudizio deve pesare origine installazione e firma piu del numero grezzo di componenti."
    ]
  }
];

const SENSITIVE_CATEGORY_WORDS = [
  "scommesse",
  "betting",
  "casino",
  "prestiti",
  "loan",
  "credito",
  "crypto",
  "finanza",
  "vpn",
  "antivirus"
];

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
  const appLabel = String(input.appLabel || "");
  const category = String(input.category || input.localCategory || "");
  const knownProfile = resolveAppProfile(packageName, appLabel, category);

  let score = Number(input.localScore || 0);
  const notes = [];
  const riskFactors = [];
  const trustFactors = [];

  if (TRUSTED_PACKAGES.has(packageName)) {
    score = Math.min(score, 25);
    notes.push("Package Google/Android attendibile: rischio locale limitato.");
    trustFactors.push("package di piattaforma attendibile");
  }
  if (knownProfile) {
    score = Math.min(score, knownProfile.cap);
    notes.push(...knownProfile.notes);
    trustFactors.push(knownProfile.trust);
  }
  if (isSensitiveCategory(packageName, appLabel, category)) {
    score += 6;
    riskFactors.push("categoria sensibile");
    notes.push("Categoria sensibile: controlla licenza, sviluppatore, pagamenti e dati richiesti.");
  }
  if (domains.some(d => d.endsWith(".top") || d.endsWith(".xyz") || d.endsWith(".ru"))) {
    score += 8;
    notes.push("Dominio con TLD da verificare.");
    riskFactors.push("domini con TLD deboli");
  }
  if (domains.length > 5) {
    score += knownProfile ? 2 : 5;
    notes.push("Molti domini leggibili nell'APK.");
    riskFactors.push("molti domini leggibili");
  }
  if (trackers.length > 3) {
    score += 8;
    notes.push("Diversi SDK tracker rilevati.");
    riskFactors.push("molti SDK tracker");
  } else if (trackers.length > 0) {
    riskFactors.push("SDK analytics/tracker presenti");
  }
  if (protectSignals.length > 0) {
    const strongProtect = protectSignals.some(signal => /sms|admin|accessibil|overlay|runtime|exec/i.test(String(signal)));
    score += strongProtect ? 14 : 6;
    notes.push(strongProtect ? "Segnali tecnici forti da verificare." : "Segnali tecnici locali presenti, da pesare con contesto e categoria.");
    riskFactors.push(strongProtect ? "segnali tecnici forti" : "segnali tecnici deboli");
  }
  if (knownProfile) {
    score = Math.min(score, knownProfile.cap);
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, notes, domains, riskFactors, trustFactors, knownProfile, category };
}

function resolveAppProfile(packageName, appLabel, category) {
  if (KNOWN_APP_PROFILES[packageName]) {
    return KNOWN_APP_PROFILES[packageName];
  }
  const haystack = `${packageName || ""} ${appLabel || ""} ${category || ""}`.toLowerCase();
  if (["crypto", "bitcoin", "wallet", "token", "exchange", "defi"].some(word => haystack.includes(word))) {
    const cryptoProfile = CATEGORY_PROFILES.find(profile => profile.category === "crypto");
    return {
      name: appLabel || packageName,
      category: cryptoProfile.category,
      trust: cryptoProfile.trust,
      cap: cryptoProfile.cap,
      notes: cryptoProfile.notes
    };
  }
  for (const profile of CATEGORY_PROFILES) {
    if (profile.match.some(word => haystack.includes(word))) {
      return {
        name: appLabel || packageName,
        category: profile.category,
        trust: profile.trust,
        cap: profile.cap,
        notes: profile.notes
      };
    }
  }
  return null;
}

function isSensitiveCategory(packageName, appLabel, category) {
  const haystack = `${packageName || ""} ${appLabel || ""} ${category || ""}`.toLowerCase();
  return SENSITIVE_CATEGORY_WORDS.some(word => haystack.includes(word));
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

function recommendationFor(score, reputation) {
  if (score < 35) {
    return "OK con controllo finale di sviluppatore, recensioni recenti e permessi.";
  }
  if (score < 68) {
    return "Usa solo se serve davvero; limita permessi non indispensabili e controlla policy privacy.";
  }
  if (reputation.knownProfile) {
    return "Categoria sensibile: non emerge malware evidente dal controllo online base, ma usa solo canale ufficiale e limita dati/permessi.";
  }
  return "Evita o cerca alternativa piu nota finche reputazione e permessi non sono chiariti.";
}

function decisionFor(score, reputation) {
  if (score < 35) return "consigliata";
  if (score < 68) return "attenzione";
  if (reputation.knownProfile) return "attenzione alta";
  return "evita";
}

function summaryFor(input, score, reputation) {
  const label = String(input.appLabel || input.packageName || "App");
  if (reputation.knownProfile) {
    return `${label}: app riconosciuta come ${reputation.knownProfile.category}. Livello ${verdictFor(score)} per categoria e permessi, non per prova automatica di malware.`;
  }
  if (reputation.trustFactors.length > 0) {
    return `${label}: segnali di affidabilita trovati. Livello ${verdictFor(score)}.`;
  }
  if (reputation.riskFactors.length > 0) {
    return `${label}: trovati ${reputation.riskFactors.slice(0, 3).join(", ")}. Livello ${verdictFor(score)}.`;
  }
  return `${label}: nessun segnale online forte nel controllo base. Livello ${verdictFor(score)}.`;
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
    summary: summaryFor(input, score, reputation),
    recommendation: recommendationFor(score, reputation),
    finalDecision: decisionFor(score, reputation),
    local: {
      score: Number(input.localScore || 0),
      verdict: String(input.localVerdict || "")
    },
    riskFactors: reputation.riskFactors,
    trustFactors: reputation.trustFactors,
    category: reputation.knownProfile ? reputation.knownProfile.category : reputation.category,
    confidence: vtResults.length > 0 || SAFE_BROWSING_API_KEY ? "alta" : "media",
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
