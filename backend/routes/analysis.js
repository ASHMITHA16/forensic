import express from "express";
import analyzeDisk from "../agents/diskAgent.js";

import analyzeLogs from "../agents/logAgent.js";

const router = express.Router();

router.post("/analyze/log", async (req, res) => {
  try {
    const { filePath } = req.body;

    const result = analyzeLogs(filePath);

    res.json({
      message: "Log analysis completed",
      data: result
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/analyze/disk", async (req, res) => {
  try {
    const { filePath } = req.body;

    const result = await analyzeDisk(filePath);

    res.json({
      message: "Disk analysis completed",
      data: result
    });

  } catch (err) {
    res.status(500).json({ error: err });
  }
});

export default router;