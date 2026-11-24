"use strict";

const { runSearch } = require("./_amfinder");

module.exports = async function handler(req, res) {
  const q = String(req.query.q || "").trim();
  const top = Number(req.query.top || 5);

  if (q.length < 2) {
    return res.status(400).json({ error: "Parameter ?q= minimal 2 karakter." });
  }

  try {
    const data = await runSearch(q, top);
    return res.status(200).json(data);
  } catch (err) {
    return res.status(502).json({ error: err.message || "Gagal mencari preset." });
  }
};
