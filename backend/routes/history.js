import express from "express";
import History from "../models/History.js";

const router = express.Router();

router.get("/history", async (req, res) => {

  try {

    const data = await History
      .find()
      .sort({ createdAt: -1 });

    res.json(data);

  } catch (err) {

    res.status(500).json({
      error: err.message
    });

  }

});

export default router;