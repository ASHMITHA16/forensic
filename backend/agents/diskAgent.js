import { exec } from "child_process";

 const analyzeDisk = (filePath) => {
  return new Promise((resolve, reject) => {

    // 🔥 Run Sleuth Kit command
    const command = `fls -r ${filePath}`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error.message);
      } else {
        // Parse output
        const parsed = parseFlsOutput(stdout);
        resolve(parsed);
      }
    });

  });
};

// 🧠 Parse fls output
const parseFlsOutput = (data) => {
  const lines = data.split("\n");

  const files = [];

  lines.forEach(line => {
    if (!line) return;

    const isDeleted = line.includes("*");

    files.push({
      raw: line,
      deleted: isDeleted
    });
  });

  return files;
};

export default analyzeDisk;