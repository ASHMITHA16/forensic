import express from "express";
import cors from "cors";
import analysisRoutes from "./routes/analysis.js";
import uploadRoutes from "./routes/upload.js";
import connectDB from "./config/db.js";   // 👈 ADD THIS

import historyRoutes from "./routes/history.js";

const app = express();

// 🔥 CONNECT DATABASE
connectDB();

app.use(cors());
app.use(express.json());

// Routes
app.use("/api", analysisRoutes);
app.use("/api", uploadRoutes);
app.use("/api", historyRoutes);

const PORT = 5000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});