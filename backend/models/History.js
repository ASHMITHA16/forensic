import mongoose from "mongoose";

const historySchema = new mongoose.Schema({
  agent: {
    type: String,
    required: true
  },

  fileName: {
    type: String,
    required: true
  },

  findings: {
    type: Number,
    default: 0
  },

  risk: {
    type: String,
    default: "low"
  },

  results: {
    type: Array,
    default: []
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

export default mongoose.model("History", historySchema);