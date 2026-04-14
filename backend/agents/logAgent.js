import fs from "fs";

const analyzeLogs = (filePath) => {
  const data = fs.readFileSync(filePath, "utf-8");

  const lines = data.split("\n");

  const results = [];

  lines.forEach((line) => {

    // 🔐 Detect failed login
    if (line.toLowerCase().includes("failed")) {
      results.push({
        type: "Failed Login",
        line: line
      });
    }

    // 🌐 Detect IP address
    const ipMatch = line.match(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    if (ipMatch) {
      results.push({
        type: "IP Detected",
        ip: ipMatch[0],
        line: line
      });
    }

    // ⚠️ Suspicious keywords
    if (
      line.toLowerCase().includes("unauthorized") ||
      line.toLowerCase().includes("error")
    ) {
      results.push({
        type: "Suspicious Activity",
        line: line
      });
    }

  });

  return results;
};

export default analyzeLogs;