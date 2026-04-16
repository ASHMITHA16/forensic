import express from "express";
import multer from "multer";
import fs from "fs";
import { generateHash } from "../services/hashService.js";
import Evidence from "../models/Evidence.js";

const router = express.Router();
const UPLOAD_DIR = "uploads";

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const filePath = req.file.path;

    // 🔐 Generate SHA-256 hash
    const hash = await generateHash(filePath);
    
    // 📄 File metadata
    const fileData = {
      filename: req.file.filename,
      path: filePath,
      hash: hash,
      size: req.file.size,
      type: req.file.mimetype,
    };

    // 🗄️ Save to DB
    const savedEvidence = await Evidence.create(fileData);

    res.json({
      message: "File uploaded & processed successfully",
      data: savedEvidence,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;