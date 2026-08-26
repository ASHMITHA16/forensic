import express from "express";
import multer from "multer";
import fs from "fs";
import path from "path";
import { generateHash } from "../services/hashService.js";
import Evidence from "../models/Evidence.js";

const router = express.Router();
const UPLOAD_DIR = "uploads";
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([".txt", ".log", ".json", ".img", ".dd", ".ad1", ".raw", ".mem", ".pcap", ".pcapng"]);
const TEXT_EXTENSIONS = new Set([".txt", ".log", ".json"]);
const TEXT_MIME_TYPES = new Set(["text/plain", "application/json", "application/octet-stream", ""]);

const validateUtf8 = async (filePath) => {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for await (const chunk of fs.createReadStream(filePath)) {
    decoder.decode(chunk, { stream: true });
  }
  decoder.decode();
};

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

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(extension)) {
      return cb(new Error("Unsupported evidence file type"));
    }
    if (TEXT_EXTENSIONS.has(extension) && !TEXT_MIME_TYPES.has(file.mimetype.toLowerCase())) {
      return cb(new Error("Log files must be text or JSON files"));
    }
    cb(null, true);
  },
});

router.post("/upload", (req, res, next) => upload.single("file")(req, res, (err) => {
  if (err) return res.status(400).json({ error: err.message });
  next();
}), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "A file is required" });
    if (req.file.size === 0) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Empty files cannot be analyzed" });
    }

    const filePath = req.file.path;
    const extension = path.extname(req.file.originalname).toLowerCase();
    if (TEXT_EXTENSIONS.has(extension)) {
      await validateUtf8(filePath);
    }

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
    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: err.message });
  }
});

export default router;