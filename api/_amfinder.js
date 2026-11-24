"use strict";

const crypto = require("crypto");
const axios = require("axios");

const BASE = "https://amfinder.web.id";
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

const CHALLENGE_KEYS = ["/api/v/2b51359f"];
const HANDSHAKE_TIMEOUT = 15000;
const SSE_MAX_MS = 90000;
const HTTP_RETRY_MAX = 2;
const RETRY_RE = /coba lagi|try again|429|terlalu banyak|too many|timed out|timeout|server|sebentar/i;
const YT_RE = /youtu\.be|youtube\.com/i;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clampN = (v) => Math.max(1, Math.min(10000, Math.floor(Number(v) || 1)));
const retryableMsg = (msg) => RETRY_RE.test(String(msg || ""));

function makeDeviceId() {
  return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
}

function postRaw(challengePath, body) {
  return axios({
    method: "POST",
    url: BASE + challengePath,
    data: body,
    timeout: HANDSHAKE_TIMEOUT,
    headers: {
      "User-Agent": UA,
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Origin": BASE,
      "Referer": BASE + "/",
    },
    validateStatus: () => true,
  })
    .then((r) => ({ status: r.status, json: r.data }))
    .catch((e) => {
      const err = new Error("handshake HTTP error: " + (e.code || e.message));
      err.status = e.response ? e.response.status : 0;
      throw err;
    });
}

async function subtleHmacRound(saltHex, payload) {
  const subtle = crypto.webcrypto ? crypto.webcrypto.subtle : globalThis.crypto.subtle;
  const key = await subtle.importKey(
    "raw",
    Buffer.from(saltHex, "hex"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return Buffer.from(await subtle.sign("HMAC", key, payload));
}

async function proofOf(salt, cid, did, ts, rounds) {
  const n = clampN(rounds);
  let buf = Buffer.from(cid + "|" + did + "|" + ts);
  for (let i = 0; i < n; i++) {
    buf = await subtleHmacRound(salt, buf);
  }
  return buf.toString("hex");
}

async function handshakeOnce(challengePath, did) {
  const s1 = await postRaw(challengePath, { did });
  const j1 = s1.json || {};
  if (s1.status !== 200 || j1.ok !== true) {
    const err = new Error(j1.error || "handshake gagal (HTTP " + s1.status + ")");
    err.status = s1.status;
    throw err;
  }

  const proof = await proofOf(j1.salt, j1.cid, did, j1.ts, j1.rounds);
  const s2 = await postRaw(challengePath, {
    cid: j1.cid,
    did,
    ts: j1.ts,
    proof,
    score: 0,
    reasons: [],
  });
  const j2 = s2.json || {};
  if (s2.status !== 200 || j2.ok !== true || !j2.token) {
    const err = new Error(j2.error || "handshake gagal (HTTP " + s2.status + ")");
    err.status = s2.status;
    throw err;
  }
  return j2.token;
}

async function discoverChallenges() {
  const found = new Set(CHALLENGE_KEYS);
  try {
    const home = await axios({
      method: "GET",
      url: BASE + "/",
      timeout: 12000,
      headers: { "User-Agent": UA },
      validateStatus: () => true,
    });
    const html = typeof home.data === "string" ? home.data : "";
    const chunks = (html.match(/\/_next\/static\/chunks\/[^"']+\.js/g) || []).slice(0, 12);
    await Promise.all(
      chunks.map(async (f) => {
        try {
          const url = f.startsWith("http") ? f : BASE + (f.startsWith("/") ? f : "/" + f);
          const r = await axios({
            url,
            timeout: 10000,
            headers: { "User-Agent": UA },
            validateStatus: () => true,
          });
          if (typeof r.data === "string") {
            (r.data.match(/\/api\/v\/[0-9a-f]{8}/g) || []).forEach((c) => found.add(c));
          }
        } catch (_) {}
      })
    );
  } catch (_) {}
  return Array.from(found);
}

async function getHandshakeToken() {
  let list = CHALLENGE_KEYS.slice();
  let did = makeDeviceId();
  let lastErr = null;

  for (let pass = 0; pass < 3; pass++) {
    for (const cpath of list) {
      try {
        return await handshakeOnce(cpath, did);
      } catch (e) {
        lastErr = e;
        if (e.status === 403) {
          did = makeDeviceId();
          await sleep(1200);
        } else if (e.status === 429) {
          await sleep(2000);
        } else if (pass === 0 && list.length === CHALLENGE_KEYS.length) {
          list = await discoverChallenges();
          if (!list.length) list = CHALLENGE_KEYS.slice();
        }
      }
    }
  }
  throw lastErr || new Error("handshake gagal");
}

function parseSseBlock(block) {
  let ev = "message";
  const datas = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) ev = line.slice(6).trim() || "message";
    else if (line.startsWith("data:")) datas.push(line.slice(5).trim());
  }
  return datas.length ? { event: ev, data: datas.join("\n") } : null;
}

function sseRun(ssePath) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let buf = "";
    let done = false;
    const acc = { logs: [], candidates: null, result: null, error: null };

    const finish = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(acc);
    };

    const timer = setTimeout(() => {
      if (acc.result || acc.error || acc.candidates) finish();
      else finish(new Error("timeout: server tidak selesai mengirim data"));
    }, SSE_MAX_MS);

    axios({
      method: "GET",
      url: BASE + ssePath,
      responseType: "stream",
      timeout: 0,
      headers: {
        "User-Agent": UA,
        "Accept": "text/event-stream",
        "Cache-Control": "no-cache",
        "Referer": BASE + "/",
      },
      validateStatus: () => true,
    })
      .then((res) => {
        if (res.status !== 200) {
          res.data?.destroy?.();
          return finish(new Error("SSE gagal (HTTP " + res.status + ")"));
        }

        res.data.on("data", (chunk) => {
          buf += chunk.toString().replace(/\r\n/g, "\n");
          let idx;
          while ((idx = buf.indexOf("\n\n")) !== -1) {
            const block = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            const ev = parseSseBlock(block);
            if (!ev) continue;

            if (ev.event === "log") {
              acc.logs.push(ev.data);
            } else if (ev.event === "candidates") {
              try {
                acc.candidates = JSON.parse(ev.data);
              } catch (_) {}
            } else if (ev.event === "result") {
              try {
                acc.result = JSON.parse(ev.data);
              } catch (_) {}
              return finish();
            } else if (ev.event === "error") {
              let msg = "terjadi kesalahan dari server";
              try {
                const j = JSON.parse(ev.data);
                msg = (j && j.message) || msg;
              } catch (_) {
                msg = ev.data || msg;
              }
              acc.error = { message: msg };
              return finish();
            }

            if (Date.now() - started > SSE_MAX_MS) return finish();
          }
        });

        const onEnd = () => {
          if (acc.result || acc.error || acc.candidates) finish();
          else finish(new Error("koneksi SSE terputus sebelum selesai"));
        };

        res.data.on("end", onEnd);
        res.data.on("error", onEnd);
        res.data.on("close", onEnd);
      })
      .catch((e) => finish(new Error("gagal membuka koneksi SSE: " + (e.code || e.message))));
  });
}

function detectSource(videoUrl) {
  return YT_RE.test(videoUrl || "") ? "youtube" : "tiktok";
}

function hashtagsOf(text) {
  const matches = String(text || "").match(/#[\p{L}\p{N}_]+/gu) || [];
  return [...new Set(matches)];
}

function fmtLink(l, idx) {
  return {
    no: idx + 1,
    tipe: l.type || null,
    judul: l.title || null,
    url: l.url,
    ukuran_file: l.size || null,
    rasio: l.ratio || null,
    thumbnail: l.thumb || null,
    diperoleh_dari: l.source || null,
    komentar: l.detail || null,
    dari_creator_video: l.byAuthor === true,
    disematkan: l.pinned === true,
    terverifikasi: l.verified === true,
  };
}

function mapFindResult(r, inputUrl = "") {
  const v = r.video || {};
  const st = v.stats || {};
  const ad = r.authorDetail || {};
  const src = detectSource(r.videoUrl || v.url || inputUrl);
  const links = Array.isArray(r.presetLinks) ? r.presetLinks : [];
  const noDataMsg =
    r.checked && r.checked.commentsDisabled
      ? "Komentar video dinonaktifkan kreator. Link preset tidak dapat diperiksa."
      : "Video ini tidak mengandung preset!";

  return {
    success: r.found !== false && links.length > 0,
    mode: "link_video",
    input: r.input || inputUrl,
    sumber: src,
    nama_creator: ad.nickname || r.author || null,
    handle_creator: ad.uniqueId ? "@" + ad.uniqueId : r.author || null,
    like: st.likes ?? null,
    comment: st.comments ?? null,
    views: st.views ?? null,
    tautan_video: r.videoUrl || v.url || inputUrl || null,
    judul_video: v.title || null,
    caption: v.description || null,
    hastag: hashtagsOf(v.description || ""),
    thumbnail: v.cover || null,
    link_preset: links.map((l) => l.url).filter(Boolean),
    preset: links.map(fmtLink),
    pesan: links.length === 0 ? noDataMsg : null,
  };
}

function mapSearchItem(it) {
  const src = detectSource(it.url || "");
  return {
    url_video: it.url,
    handle: it.handle || null,
    snippet_caption: it.snippet || null,
    hastag: hashtagsOf(it.snippet || ""),
    thumbnail: it.thumb || null,
    durasi_detik: it.duration ?? null,
    views: it.stats?.playCount ?? null,
    like: it.stats?.likeCount ?? null,
    sumber: src,
  };
}

async function runFind(inputUrl) {
  let lastErr = null;
  for (let attempt = 1; attempt <= HTTP_RETRY_MAX; attempt++) {
    try {
      const token = await getHandshakeToken();
      const got = await sseRun(`/api/find?url=${encodeURIComponent(inputUrl)}&t=${encodeURIComponent(token)}`);
      if (got.error) throw new Error(got.error.message);
      if (got.result) {
        if (got.result.ok === false) throw new Error(got.result.error || "gagal memproses link");
        return mapFindResult(got.result, inputUrl);
      }
      throw new Error("tidak ada data diterima dari server");
    } catch (e) {
      lastErr = e;
      if (retryableMsg(e.message) && attempt < HTTP_RETRY_MAX) {
        await sleep(1200);
        continue;
      }
      break;
    }
  }
  throw lastErr || new Error("pemindaian gagal");
}

async function runSearch(keyword, top = 3) {
  let searchData = null;

  for (let attempt = 1; attempt <= HTTP_RETRY_MAX; attempt++) {
    try {
      const token = await getHandshakeToken();
      const got = await sseRun(`/api/search?mode=pick&q=${encodeURIComponent(keyword)}&t=${encodeURIComponent(token)}`);
      if (got.error) throw new Error(got.error.message);
      searchData = {
        items: got.candidates?.items || [],
        meta: got.result || null,
      };
      break;
    } catch (e) {
      if (retryableMsg(e.message) && attempt < HTTP_RETRY_MAX) {
        await sleep(1200);
        continue;
      }
      throw e;
    }
  }

  const items = searchData?.items || [];
  const limit = Math.max(1, Math.min(5, Number(top) || 3));
  const targets = items.slice(0, limit);
  const scanned = [];

  for (let i = 0; i < targets.length; i++) {
    const it = targets[i];
    if (!it || !it.url) continue;
    if (i > 0) await sleep(600);
    try {
      const data = await runFind(it.url);
      scanned.push({ no: i + 1, url: it.url, data });
    } catch (e) {
      scanned.push({ no: i + 1, url: it.url, error: e.message || String(e) });
    }
  }

  const totalPreset = scanned.reduce(
    (acc, item) => acc + ((item.data?.link_preset && item.data.link_preset.length) || 0),
    0
  );

  return {
    success: totalPreset > 0,
    mode: "pencarian_kata_kunci",
    input: keyword,
    total_hasil: items.length,
    total_link_preset: totalPreset,
    hasil_pencarian: items.map(mapSearchItem),
    semua_hasil_dipindai: scanned,
  };
}

module.exports = { runFind, runSearch };
