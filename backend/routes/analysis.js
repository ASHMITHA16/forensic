import express from "express";
import analyzeDisk from "../agents/diskAgent.js";
import analyzeLogs from "../agents/logAgent.js";
import analyzeNetwork from "../agents/networkAgent.js";
const router = express.Router();

router.post("/analyze/log", async (req, res) => {
  try {
    const { filePath } = req.body;

    const result =  analyzeLogs(filePath);

    res.json({
      message: "Log analysis completed",
      data: result
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




router.post("/analyze/network", async (req, res) => {
  try {
    const { filePath } = req.body;

    const result = await analyzeNetwork(filePath); // ✅ FIX

    res.json({ data: result }); // also wrap properly
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;