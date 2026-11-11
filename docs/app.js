// CSIX Phish — port JavaScript dari heuristik Go di internal/phish/phish.go
// Berjalan 100% offline di browser. Dipertahankan sinkron dengan versi CLI.
"use strict";

const MULTI_PART_SUFFIXES = new Set([
  "co.uk","org.uk","ac.uk","gov.uk","co.id","or.id","ac.id","sch.id","web.id",
  "net.id","go.id","my.id","biz.id","com.au","net.au","org.au","co.jp","or.jp",
  "ne.jp","ac.jp","co.in","net.in","org.in","ac.in","gov.in","com.br","com.mx",
  "com.ar","com.tr","com.cn","com.tw","com.hk","com.sg","com.my","co.th",
  "co.nz","co.za","com.ng","com.eg","com.sa","com.pk","com.ph","com.vn",
]);

const RISKY_TLDS = new Set([
  "tk","ml","ga","cf","gq","xyz","top","buzz","click","country","work","loan",
  "men","mom","party","review","stream","gdn","icu","cam","rest","cyou","sbs",
  "zip","mov","monster","quest",
]);

const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy",
  "shorturl.at","ow.ly","buff.ly","rebrand.ly","s.id","bit.do","soo.gd",
  "shorte.st","lnkd.in",
]);

const BRANDS = [
  "paypal","google","facebook","instagram","whatsapp","youtube","netflix",
  "amazon","apple","microsoft","outlook","linkedin","twitter","stripe",
  "coinbase","binance","metamask","steam","discord","dropbox","dhl","fedex",
  "usps","uber","airbnb","spotify","tiktok","roblox",
  // merek Indonesia
  "bca","mandiri","bri","bni","cimb","ovo","dana","gopay","gojek",
  "tokopedia","shopee","bukalapak","lazada","linkaja","jenius","seabank","jago",
];

const PATH_KEYWORDS = [
  "login","signin","sign-in","sign_in","logon","verify","verification",
  "validate","secure","security","account","update","confirm","bank",
  "banking","invoice","payment","wallet","unlock","recover","suspended",
  "limited","kyc","otp","credential","webscr","authorize","retail",
];

const LEET = { "0":"o","1":"l","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","!":"i" };

function check(raw) {
  let u;
  try {
    let s = raw.trim().replace(/^["'<>()]+|["'<>()]+$/g, "");
    if (!s.includes("://")) s = "http://" + s;
    u = new URL(s);
  } catch (e) {
    throw new Error("URL tidak valid");
  }

  const host = u.hostname.toLowerCase();
  const signals = [];
  const add = (id, desc, weight) => signals.push({ id, desc, weight });

  const { domain, sld, tld, labels } = splitDomain(host);

  // identitas host
  const ip = parseIPv4(host);
  if (ip !== null) {
    if (isPrivateIP(ip)) add("private-ip", "Host adalah IP privat/loopback (target internal)", 5);
    else add("ip-host", "Host berupa alamat IP mentah, bukan domain", 35);
  } else if (/^0x[0-9a-f]+$/i.test(host) || /^[0-9]+$/.test(host)) {
    add("numeric-host", "Host berupa angka desimal/hex (obfuskasi IP)", 30);
  }
  if (host.includes("xn--")) add("punycode", "Host punycode (xn--) — kemungkinan serangan homograph IDN", 30);
  if (/[^\x00-\x7f]/.test(host)) add("non-ascii-host", "Host mengandung karakter non-ASCII", 20);

  // TLD & shortener
  if (tld && RISKY_TLDS.has(tld)) add("risky-tld", `TLD berisiko tinggi yang sering dipakai phishing (.${tld})`, 15);
  if (SHORTENERS.has(domain) || SHORTENERS.has(host)) add("shortener", "URL shortener — tujuan akhir tidak bisa dinilai dari link", 20);

  // karakter domain
  const hyphens = (sld.match(/-/g) || []).length;
  if (hyphens >= 3) add("many-hyphens", `Banyak tanda hubung pada domain (${hyphens})`, 10);
  if (labels.length >= 5) add("deep-subdomain", `Subdomain bertingkat dalam (${labels.length} label)`, 10);
  else if (labels.length === 4) add("deep-subdomain", "Subdomain bertingkat (4 label)", 5);

  // skema & port
  const isLocal = (ip !== null && isPrivateIP(ip)) || host === "localhost" || host.startsWith("localhost.");
  if (!isLocal && u.protocol !== "https:") add("http-scheme", "Skema bukan HTTPS — lalu lintas tidak terenkripsi", 5);
  if (!isLocal && u.port && u.port !== "80" && u.port !== "443") add("nonstandard-port", `Port tidak umum (:${u.port})`, 10);
  if (u.username || u.password) add("userinfo", "URL memuat kredensial (user:pass@host) — trik redirect klasik", 30);

  // isi URL
  const full = u.toString();
  if (full.length > 120) add("url-too-long", `URL sangat panjang (${full.length} karakter)`, 8);
  const enc = full.match(/%[0-9A-Fa-f]{2}/g) || [];
  if (enc.length >= 3) add("excessive-encoding", `Banyak encoding %XX (${enc.length}) — kemungkinan menyembunyikan tujuan`, 10);
  const query = u.search.replace(/^\?/, "");
  if (/(?:password|passwd|pwd|email|username|user|login)=/i.test(query)) {
    add("credential-params", "Query mengandung parameter kredensial (password/email/user)", 12);
  }
  const kw = keywordsIn(u.pathname + "?" + query);
  if (kw.length > 0) {
    const w = Math.min(8 * kw.length, 24);
    add("suspicious-keywords", `Kata kunci mencurigakan: ${kw.join(", ")}`, w);
  }

  // typosquatting / merek
  checkBrands(sld, host, add);

  // total & level
  let score = signals.reduce((a, s) => a + s.weight, 0);
  score = Math.min(100, score);
  let level = "LOW";
  if (score >= 70) level = "CRITICAL";
  else if (score >= 40) level = "DANGEROUS";
  else if (score >= 15) level = "SUSPICIOUS";

  return { url: full, host, domain, score, level, signals };
}

function splitDomain(host) {
  const labels = host.split(".");
  if (labels.length >= 3 && MULTI_PART_SUFFIXES.has(labels.slice(-2).join("."))) {
    return {
      domain: labels.slice(-3).join("."),
      sld: labels[labels.length - 3],
      tld: labels[labels.length - 1],
      labels,
    };
  }
  if (labels.length >= 2) {
    return {
      domain: labels.slice(-2).join("."),
      sld: labels[labels.length - 2],
      tld: labels[labels.length - 1],
      labels,
    };
  }
  return { domain: host, sld: host, tld: "", labels };
}

function checkBrands(sld, host, add) {
  const norm = leetFold(sld);
  for (const b of BRANDS) {
    if (norm === b) {
      if (sld !== b) add("typosquat", `Domain menyerupai merek "${b}" (substitusi karakter)`, 40);
      continue;
    }
    const d = levenshtein(norm, b);
    if (d === 1 && b.length >= 5) { add("typosquat", `Domain mendekati merek "${b}" (jarak ${d})`, 40); continue; }
    if (d === 2 && b.length >= 6) { add("brand-similar", `Domain mirip merek "${b}"`, 20); continue; }
    let matched = false;
    for (const tok of norm.split("-")) {
      if (tok === b && sld !== b) { add("brand-token", `Domain mengandung merek "${b}"`, 35); matched = true; break; }
    }
    if (!matched && norm.includes(b)) add("brand-substring", `Domain mengandung nama merek "${b}"`, 15);
  }
  // merek di subdomain
  const parts = host.split(".");
  let regLabels = 2;
  if (parts.length >= 3 && MULTI_PART_SUFFIXES.has(parts.slice(-2).join("."))) regLabels = 3;
  const sub = parts.length > regLabels ? parts.slice(0, parts.length - regLabels) : [];
  outer: for (const l of sub) {
    const nl = leetFold(l);
    for (const b of BRANDS) {
      if (nl === b || (b.length >= 5 && levenshtein(nl, b) <= 1)) {
        add("brand-subdomain", `Merek "${b}" muncul di subdomain — trik penipuan`, 35);
        break outer;
      }
    }
  }
}

function keywordsIn(s) {
  const low = s.toLowerCase();
  return PATH_KEYWORDS.filter((k) => low.includes(k));
}

function leetFold(s) {
  return s.toLowerCase().replace(/[013457@$!]/g, (c) => LEET[c] || c);
}

function levenshtein(a, b) {
  const la = a.length, lb = b.length;
  let prev = Array.from({ length: lb + 1 }, (_, j) => j);
  let curr = new Array(lb + 1);
  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[lb];
}

function parseIPv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const oct = m.slice(1).map(Number);
  if (oct.some((n) => n > 255)) return null;
  return oct;
}

function isPrivateIP(oct) {
  const [a, b] = oct;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 0) return true;
  return false;
}

// ---------- UI ----------

const LEVEL_CLASS = { LOW: "low", SUSPICIOUS: "sus", DANGEROUS: "danger", CRITICAL: "crit" };

function render(res) {
  const el = (id) => document.getElementById(id);
  el("result").hidden = false;
  el("score").textContent = res.score;
  el("level").textContent = res.level;
  el("level").className = "level " + LEVEL_CLASS[res.level];
  el("barfill").style.width = res.score + "%";
  el("barfill").className = "bar-fill " + LEVEL_CLASS[res.level];
  el("meta").textContent = `host: ${res.host}` + (res.domain !== res.host ? ` · domain: ${res.domain}` : "");

  const box = el("signals");
  box.innerHTML = "";
  if (res.signals.length === 0) {
    const p = document.createElement("p");
    p.className = "clean";
    p.textContent = "✓ Tidak ada sinyal risiko yang terdeteksi.";
    box.appendChild(p);
    return;
  }
  for (const s of res.signals) {
    const row = document.createElement("div");
    row.className = "signal";
    const w = document.createElement("span");
    w.className = "weight";
    w.textContent = "[" + s.weight + "]";
    const d = document.createElement("span");
    d.textContent = s.desc;
    row.append(w, d);
    box.appendChild(row);
  }
}

function run(raw) {
  try {
    render(check(raw));
  } catch (e) {
    document.getElementById("result").hidden = true;
    alert(e.message);
  }
}

document.getElementById("check").addEventListener("click", () => {
  const v = document.getElementById("url").value;
  if (v) run(v);
});
document.getElementById("url").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.value) run(e.target.value);
});
document.querySelectorAll(".chip").forEach((b) => {
  b.addEventListener("click", () => {
    document.getElementById("url").value = b.dataset.url;
    run(b.dataset.url);
  });
});
