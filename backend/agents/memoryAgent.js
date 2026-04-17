import fs from "fs";

const analyzeMemory = (filePath) => {
  const data = fs.readFileSync(filePath, "utf-8");
  const lines = data.split("\n");

  const results = [];

  lines.forEach((process) => {
    if (!process.trim()) return;

    // 🔥 Suspicious process detection
    if (
      process.toLowerCase().includes("malware") ||
      process.toLowerCase().includes("unknown")
    ) {
      results.push({
        type: "Suspicious Process",
        process: process,
      });
    } else {
      results.push({
        type: "Normal Process",
        process: process,
      });
    }
  });

  return results;
};

export default analyzeMemory;