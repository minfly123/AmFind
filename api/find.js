"use strict";

const { runFind } = require("./_amfinder");

module.exports = async function handler(req, res) {
  const url = String(req.query.url || "").trim();
  if (!url) {
    return res.status(400).json({ error: "Parameter ?url= wajib diisi." });
  }

  try {
    const data = await runFind(url);
    return res.status(200).json(data);
  } catch (err) {
    return res.status(502).json({ error: err.message || "Gagal memindai video." });
  }
};
