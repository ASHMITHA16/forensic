import mongoose from "mongoose";

const EvidenceSchema = new mongoose.Schema({
  filename: String,
  path: String,
  hash: String,
  size: Number,
  type: String,
  uploadedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("Evidence", EvidenceSchema);