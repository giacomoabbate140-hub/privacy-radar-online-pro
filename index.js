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

const VERIFIED_RISK_LEVELS = {
  VERIFIED_SAFE: "verified_safe",
  VERIFIED_SENSITIVE: "verified_sensitive",
  KNOWN_PRIVACY_HEAVY: "known_privacy_heavy",
  UNKNOWN: "unknown",
  SUSPICIOUS_CLONE: "suspicious_clone"
};

const KNOWN_APP_PROFILES = {
  "com.easypark.android": {
    name: "EasyPark",
    category: "parcheggio/mobilita",
    trust: "app parcheggio nota/riconoscibile",
    cap: 56,
    notes: [
      "App riconosciuta come parcheggio/mobilita: posizione, rete e pagamenti sono coerenti con la funzione.",
      "Il rischio va alzato solo con accessibilita, SMS, installazione esterna o segnali tecnici forti."
    ]
  },
  "it.telepass.pay": {
    name: "Telepass",
    category: "parcheggio/mobilita",
    trust: "app mobilita/pagamenti nota",
    cap: 60,
    notes: [
      "App mobilita/pagamenti riconoscibile: posizione e pagamenti possono essere coerenti.",
      "Verifica comunque sviluppatore ufficiale e permessi non indispensabili."
    ]
  },
  "it.posteitaliane.posteapp.appbpol": {
    name: "BancoPosta",
    category: "banca/poste/servizi ufficiali",
    trust: "app Poste riconoscibile",
    cap: 62,
    notes: [
      "App Poste/banca riconoscibile: identita, notifiche e fotocamera possono essere coerenti.",
      "Non valutare solo il numero di permessi: controlla origine, firma e segnali tecnici forti."
    ]
  },
  "com.posteitaliane.spim": {
    name: "Poste Italiane",
    category: "banca/poste/servizi ufficiali",
    trust: "app Poste riconoscibile",
    level: VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE,
    cap: 34,
    notes: [
      "App Poste riconosciuta: identita, pagamenti, notifiche e fotocamera possono essere coerenti con servizi ufficiali.",
      "Rischio tecnico basso se origine Play Store, package e firma sono coerenti; resta categoria privacy sensibile."
    ]
  },
  "posteitaliane.posteapp.apppostepay": {
    name: "Postepay",
    category: "banca/poste/servizi ufficiali",
    trust: "app Postepay riconoscibile",
    cap: 62,
    notes: [
      "App Postepay riconoscibile: pagamenti e identita sono coerenti con la funzione.",
      "Il rischio diventa alto con package/firma non coerenti, APK esterni o permessi fuori contesto."
    ]
  },
  "it.pagopa.io.app": {
    name: "IO",
    category: "banca/poste/servizi ufficiali",
    trust: "app pubblica riconoscibile",
    cap: 58,
    notes: [
      "App IO riconoscibile: notifiche, identita e servizi pubblici sono coerenti.",
      "Valutare origine ufficiale, firma e permessi extra."
    ]
  },
  "posteitaliane.posteapp.appposteid": {
    name: "PosteID",
    category: "identita digitale/SPID",
    trust: "app PosteID riconoscibile",
    cap: 62,
    notes: [
      "App PosteID riconoscibile: SPID, QR, documenti e biometria possono essere coerenti con la funzione.",
      "Per app identita digitale il rischio va letto come sensibilita dei dati, non come pericolo tecnico automatico."
    ]
  },
  "it.ipzs.cieid": {
    name: "CieID",
    category: "identita digitale/CIE",
    trust: "app CieID riconoscibile",
    cap: 58,
    notes: [
      "App CieID riconoscibile: NFC, QR, documenti e biometria possono essere coerenti con l'accesso ai servizi online.",
      "Categoria sensibile ma non rischio alto senza segnali critici, origine anomala o firma cambiata."
    ]
  },
  "com.paypal.android.p2pmobile": {
    name: "PayPal",
    category: "pagamenti",
    trust: "app pagamenti riconoscibile",
    cap: 62,
    notes: [
      "App pagamenti riconoscibile: rete, identita e notifiche sono coerenti con la funzione.",
      "Il rischio sale se l'origine non e ufficiale o se compaiono accessibilita/overlay non spiegati."
    ]
  },
  "com.satispay.customer": {
    name: "Satispay",
    category: "pagamenti",
    trust: "app pagamenti riconoscibile",
    cap: 60,
    notes: [
      "App pagamenti riconoscibile: pagamenti e identita sono coerenti.",
      "Verifica origine installazione e limita permessi non necessari."
    ]
  },
  "com.whatsapp": {
    name: "WhatsApp",
    category: "messaggistica/social",
    trust: "app messaggistica nota",
    level: VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY,
    cap: 48,
    notes: [
      "App messaggistica nota: contatti, media, microfono e notifiche possono essere coerenti.",
      "Il rischio principale e privacy/dati condivisi, non per forza malware."
    ]
  },
  "com.whatsapp.w4b": {
    name: "WhatsApp Business",
    category: "messaggistica/social",
    trust: "app messaggistica business nota",
    level: VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY,
    cap: 48,
    notes: [
      "App messaggistica business nota: contatti, media, microfono, camera e notifiche possono essere coerenti.",
      "Il rischio principale e privacy/dati condivisi, non malware automatico se origine e firma sono coerenti."
    ]
  },
  "com.instagram.android": {
    name: "Instagram",
    category: "social",
    trust: "app social nota",
    level: VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY,
    cap: 48,
    notes: [
      "App social nota: camera, media, rete e tracker possono essere coerenti con il modello pubblicitario.",
      "Valuta privacy, dati condivisi e permessi attivi."
    ]
  },
  "com.facebook.katana": {
    name: "Facebook",
    category: "social",
    trust: "app social nota",
    level: VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY,
    cap: 48,
    notes: [
      "App social nota: molti SDK e permessi possono essere coerenti con funzioni social/pubblicitarie.",
      "Il giudizio deve separare privacy commerciale da pericolo tecnico."
    ]
  },
  "com.nexse.mobile.bos.eurobet": {
    name: "Eurobet",
    category: "scommesse",
    trust: "app nota/riconoscibile",
    level: VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE,
    cap: 34,
    notes: [
      "App scommesse riconosciuta: categoria sensibile per privacy, pagamenti, identita e posizione.",
      "Rischio tecnico basso se origine, firma e segnali sono coerenti; resta una categoria da usare con attenzione."
    ]
  },
  "it.goldbet.mobile": {
    name: "Goldbet",
    category: "scommesse",
    trust: "app scommesse riconoscibile",
    level: VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE,
    cap: 34,
    notes: [
      "App scommesse riconoscibile: categoria sensibile per privacy, pagamenti, identita e posizione.",
      "Rischio tecnico basso se origine, firma e segnali sono coerenti; resta una categoria da usare con attenzione."
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
    category: "parcheggio/mobilita",
    match: ["easypark", "isypark", "parking", "parcheggio", "sosta", "mobility", "mobilita", "telepass", "mooneygo", "mycicero", "paybyphone", "trasport"],
    cap: 58,
    trust: "categoria riconosciuta: parcheggio/mobilita",
    notes: [
      "App parcheggio/mobilita: posizione, rete, notifiche e pagamenti sono spesso coerenti con la funzione.",
      "Il rischio diventa alto solo se compaiono permessi fuori contesto come accessibilita, SMS, installazione esterna o device admin."
    ]
  },
  {
    category: "banca/poste/servizi ufficiali",
    match: ["poste", "postepay", "bancoposta", "io.italia", "pagopa", "inps", "agenziaentrate", "banca", "bank", "paypal", "nexi", "satispay", "revolut", "wise", "buddybank", "unicredit", "intesa", "bnl", "fineco", "hype"],
    cap: 64,
    trust: "categoria riconosciuta: banca/poste/servizi ufficiali",
    notes: [
      "App banca/poste/servizi ufficiali: pagamenti, identita, notifiche e fotocamera per documenti/QR possono essere coerenti.",
      "Il rischio va alzato soprattutto con accessibilita, SMS, installazione esterna, overlay o segnali malware reali."
    ]
  },
  {
    category: "identita digitale/SPID/CIE",
    match: ["posteid", "spid", "cieid", "cartaidentita", "identita digitale", "ipzs"],
    cap: 62,
    trust: "categoria riconosciuta: identita digitale",
    notes: [
      "App identita digitale: documenti, QR, NFC, biometria e notifiche possono essere coerenti.",
      "Il rischio diventa alto solo con origine non ufficiale, firma cambiata o permessi tecnici fuori contesto."
    ]
  },
  {
    category: "social/messaggistica",
    match: ["whatsapp", "telegram", "signal", "instagram", "facebook", "tiktok", "snapchat", "twitter", "x.com", "discord", "messenger", "dating", "tinder", "bumble"],
    cap: 66,
    trust: "categoria riconosciuta: social/messaggistica",
    notes: [
      "App social/messaggistica: contatti, media, microfono e notifiche possono essere coerenti.",
      "Il rischio va letto come privacy/dati condivisi, non automaticamente come malware."
    ]
  },
  {
    category: "giochi",
    match: ["game", "games", "gioco", "giochi", "unity", "roblox", "minecraft", "supercell", "clash", "fortnite", "pubg", "casino game"],
    cap: 62,
    trust: "categoria riconosciuta: giochi",
    notes: [
      "App gioco: SDK pubblicitari, analytics e acquisti in-app sono frequenti.",
      "Il rischio cresce con accessibilita, SMS, installazione esterna o domini sospetti."
    ]
  },
  {
    category: "foto/video/editor",
    match: ["photo", "foto", "camera", "video", "editor", "gallery", "galleria", "snapseed", "capcut", "canva"],
    cap: 60,
    trust: "categoria riconosciuta: foto/video/editor",
    notes: [
      "App foto/video: camera, media e rete possono essere coerenti.",
      "Controlla se carica contenuti su cloud o condivide dati con terze parti."
    ]
  },
  {
    category: "trasporti/viaggi",
    match: ["train", "treno", "trenitalia", "italo", "ryanair", "booking", "hotel", "taxi", "uber", "moovit", "maps", "mappe"],
    cap: 60,
    trust: "categoria riconosciuta: trasporti/viaggi",
    notes: [
      "App trasporti/viaggi: posizione, notifiche e pagamenti sono spesso coerenti.",
      "Il rischio sale con origine non ufficiale o permessi fuori contesto."
    ]
  },
  {
    category: "scommesse",
    match: ["scommess", "betting", "casino", "eurobet", "goldbet", "snai", "sisal", "bet365", "poker", "bingo"],
    level: VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE,
    cap: 34,
    trust: "categoria riconosciuta: scommesse/casino",
    notes: [
      "App scommesse/casino: categoria sensibile per pagamenti, identita, posizione e uso account.",
      "Se installata da Play Store e senza segnali critici, il rischio tecnico resta basso; la sensibilita riguarda privacy e uso responsabile."
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
  const signature = String(input.signature || "");
  const installSource = String(input.installSource || "");
  const knownProfile = resolveAppProfile(packageName, appLabel, category);
  const suspiciousBrandUse = isSuspiciousBrandUse(packageName, appLabel, domains);
  const suspiciousSocialClone = isSuspiciousSocialClone(packageName, appLabel);
  const verifiedContext = hasVerifiedContext(input, knownProfile, suspiciousBrandUse);
  const trustedInstalledContext = hasTrustedInstalledContext(input);

  let score = Number(input.localScore || 0);
  const notes = [];
  const riskFactors = [];
  const trustFactors = [];

  if (TRUSTED_PACKAGES.has(packageName)) {
    score = Math.min(score, 25);
    notes.push("Package Google/Android attendibile: rischio locale limitato.");
    trustFactors.push("package di piattaforma attendibile");
  }
  if (hasSignatureHash(signature)) {
    trustFactors.push("firma/hash tecnico ricevuto");
  } else if (/installata|apk/i.test(String(input.source || ""))) {
    notes.push("Firma non ricevuta o non leggibile: verifica online non completa.");
    riskFactors.push("firma non verificata");
  }
  if (/google play store/i.test(installSource)) {
    trustFactors.push("origine Google Play");
  } else if (/apk locale|manual/i.test(installSource)) {
    score += knownProfile ? 4 : 10;
    riskFactors.push("APK locale/manuale");
    notes.push("Origine APK locale/manuale: controlla che provenga dal canale ufficiale.");
  } else if (/origine:/i.test(installSource) && !/installatore Android di sistema|non disponibile/i.test(installSource)) {
    score += knownProfile ? 3 : 7;
    riskFactors.push("origine installazione da verificare");
    notes.push("Origine installazione non Play Store: verifica store, sviluppatore e firma.");
  }
  if (knownProfile) {
    score = Math.min(score, suspiciousBrandUse ? Math.max(knownProfile.cap, 86) : knownProfile.cap);
    notes.push(...knownProfile.notes);
    if (suspiciousBrandUse) {
      notes.push("Nome o package usa un marchio sensibile ma con segnali non ufficiali: possibile clone/phishing da verificare.");
      riskFactors.push("marchio sensibile non coerente");
    } else {
      trustFactors.push(knownProfile.trust);
    }
  }
  if (suspiciousSocialClone) {
    score = Math.max(score, 82);
    notes.push("Marchio social/messaggistica usato da package non ufficiale: possibile clone o mod da evitare.");
    riskFactors.push("possibile clone social");
  }
  if (isSensitiveCategory(packageName, appLabel, category)) {
    if (verifiedContext) {
      trustFactors.push("categoria sensibile ma contesto verificato");
      notes.push("Categoria sensibile: non aumenta il rischio tecnico se origine, firma e segnali sono coerenti.");
    } else {
      score += 6;
      riskFactors.push("categoria sensibile");
      notes.push("Categoria sensibile: controlla licenza, sviluppatore, pagamenti e dati richiesti.");
    }
  }
  if (hasWeakDomains(domains)) {
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
    const strongProtect = hasStrongProtectSignals(protectSignals);
    score += strongProtect ? 14 : 6;
    notes.push(strongProtect ? "Segnali tecnici forti da verificare." : "Segnali tecnici locali presenti, da pesare con contesto e categoria.");
    riskFactors.push(strongProtect ? "segnali tecnici forti" : "segnali tecnici deboli");
  }
  if (knownProfile) {
    score = Math.min(score, suspiciousBrandUse ? 92 : knownProfile.cap);
    if (verifiedContext && !hasStrongProtectSignals(protectSignals) && !hasWeakDomains(domains)) {
      score = Math.min(score, verifiedScoreCap(knownProfile));
    }
  } else if (trustedInstalledContext && !suspiciousSocialClone && !hasStrongProtectSignals(protectSignals) && !hasWeakDomains(domains)) {
    score = Math.min(score, 62);
    notes.push("Origine Play Store e firma ricevuta: rischio alto limitato in assenza di segnali tecnici forti.");
    trustFactors.push("origine/firma coerenti");
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, notes, domains, riskFactors, trustFactors, knownProfile, category, signature, installSource };
}

function hasVerifiedContext(input, knownProfile, suspiciousBrandUse) {
  if (!knownProfile || suspiciousBrandUse) return false;
  const signature = String(input.signature || "");
  const installSource = String(input.installSource || "");
  const hasSignature = hasSignatureHash(signature);
  const playStore = /google play store/i.test(installSource);
  return hasSignature && playStore;
}

function hasTrustedInstalledContext(input) {
  const signature = String(input.signature || "");
  const installSource = String(input.installSource || "");
  const hasSignature = hasSignatureHash(signature);
  const playStore = /google play store/i.test(installSource);
  return hasSignature && playStore;
}

function verifiedScoreCap(profile) {
  switch (profile.level) {
    case VERIFIED_RISK_LEVELS.VERIFIED_SAFE:
      return 28;
    case VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE:
      return 34;
    case VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY:
      return 32;
    default:
      return Math.min(profile.cap || 62, 50);
  }
}

function hasSignatureHash(signature) {
  return /SHA-256\s*:?\s*[A-F0-9]{32,}/i.test(String(signature || ""));
}

function hasWeakDomains(domains) {
  return domains.some(d => d.endsWith(".top") || d.endsWith(".xyz") || d.endsWith(".ru"));
}

function hasStrongProtectSignals(protectSignals) {
  return protectSignals.some(signal => /sms|admin|accessibil|overlay|runtime|exec/i.test(String(signal)));
}

function signatureStatusFor(reputation) {
  if (hasSignatureHash(reputation.signature)) {
    if (reputation.knownProfile) {
      return "impronta SHA-256 ricevuta; app riconosciuta per package/categoria, firma ufficiale da confrontare se disponibile.";
    }
    return "impronta SHA-256 ricevuta; utile per confronti futuri e rilevare cambi anomali.";
  }
  return "non disponibile: controllo firma online incompleto.";
}

function installSourceStatusFor(reputation) {
  const source = String(reputation.installSource || "");
  if (/google play store/i.test(source)) {
    return "origine Play Store: fattore positivo, resta da verificare firma/reputazione.";
  }
  if (/apk locale|manual/i.test(source)) {
    return "APK locale/manuale: richiede controllo piu prudente.";
  }
  if (/origine:/i.test(source)) {
    return source.replace(/^Origine:\s*/i, "origine rilevata: ");
  }
  return "origine non disponibile.";
}

function isSuspiciousBrandUse(packageName, appLabel, domains) {
  const haystack = `${packageName || ""} ${appLabel || ""}`.toLowerCase();
  const brandLike = /poste|postepay|bancoposta|spid|inps|agenziaentrate|paypal|nexi|satispay/.test(haystack);
  if (!brandLike) return false;
  const officialPackage = /^(posteitaliane\.|it\.poste|it\.posteitaliane|com\.posteitaliane|it\.ipzs|it\.pagopa|it\.inps|it\.agenziaentrate|com\.paypal|it\.nexi|com\.satispay)/.test(packageName || "");
  const weakDomain = domains.some(d => d.endsWith(".top") || d.endsWith(".xyz") || d.endsWith(".ru"));
  const lureWords = /bonus|gratis|free|apk|mod|credito|premio|gift|win/.test(haystack);
  return !officialPackage || weakDomain || lureWords;
}

function isSuspiciousSocialClone(packageName, appLabel) {
  const pkg = String(packageName || "").toLowerCase();
  const haystack = `${packageName || ""} ${appLabel || ""}`.toLowerCase();
  const brandLike = /whatsapp|facebook|instagram|telegram|signal/.test(haystack);
  if (!brandLike) return false;
  const official = new Set([
    "com.whatsapp",
    "com.whatsapp.w4b",
    "com.facebook.katana",
    "com.instagram.android",
    "org.telegram.messenger",
    "org.thoughtcrime.securesms"
  ]);
  const modWords = /gbwhatsapp|gb whatsapp|fmwhatsapp|fm whatsapp|yowhatsapp|yo whatsapp|whatsapp plus|wa plus|mod|clone|unofficial/.test(haystack);
  return !official.has(pkg) && (brandLike || modWords);
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
  if (score < 70) return "rischio medio";
  return "rischio alto";
}

function recommendationFor(score, reputation) {
  if (reputation.knownProfile?.level === VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY && score < 35) {
    return "App ufficiale/nota: rischio tecnico basso. Resta attenzione privacy per contatti, media, notifiche e dati condivisi.";
  }
  if (reputation.knownProfile?.level === VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE && score < 35) {
    return "App riconosciuta: rischio tecnico basso. Resta categoria sensibile, quindi usa solo canale ufficiale e limita permessi non indispensabili.";
  }
  if (score < 35) {
    return "OK con controllo finale di sviluppatore, recensioni recenti e permessi.";
  }
  if (score < 70) {
    return "Usa solo se serve davvero; limita permessi non indispensabili e controlla policy privacy.";
  }
  if (reputation.knownProfile) {
    return "Categoria sensibile: non emerge malware evidente dal controllo online base, ma usa solo canale ufficiale e limita dati/permessi.";
  }
  return "Evita o cerca alternativa piu nota finche reputazione e permessi non sono chiariti.";
}

function decisionFor(score, reputation) {
  if (reputation.knownProfile?.level === VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY && score < 35) return "consigliata con attenzione privacy";
  if (reputation.knownProfile?.level === VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE && score < 35) return "consigliata con attenzione privacy";
  if (score < 35) return "consigliata";
  if (score < 70) return "attenzione";
  if (reputation.knownProfile) return "attenzione alta";
  return "evita";
}

function summaryFor(input, score, reputation) {
  const label = String(input.appLabel || input.packageName || "App");
  if (reputation.knownProfile) {
    if (reputation.knownProfile.level === VERIFIED_RISK_LEVELS.KNOWN_PRIVACY_HEAVY && score < 35) {
      return `${label}: app ufficiale/nota riconosciuta come ${reputation.knownProfile.category}. Rischio tecnico basso; attenzione privacy per dati e permessi.`;
    }
    if (reputation.knownProfile.level === VERIFIED_RISK_LEVELS.VERIFIED_SENSITIVE && score < 35) {
      return `${label}: app riconosciuta come ${reputation.knownProfile.category}. Rischio tecnico basso; categoria sensibile per privacy/pagamenti.`;
    }
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
    signatureStatus: signatureStatusFor(reputation),
    installSourceStatus: installSourceStatusFor(reputation),
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
