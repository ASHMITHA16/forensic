import { exec } from "child_process";
import path from "path";

const analyzeDisk = (filePath) => {
  return new Promise((resolve, reject) => {

    const fullPath = path.resolve(filePath);
    console.log("Analyzing disk at:", fullPath);

    const command = `"C:\\Users\\Ashmitha U\\Downloads\\sleuthkit-4.14.0-win32\\sleuthkit-4.14.0-win32\\bin\\fls.exe" -r "${fullPath}"`;

    console.log("Running:", command);

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error("FLS Error:", error.message);
        return resolve([]);
      }

      const lines = stdout.split("\n");
      const results = [];

      lines.forEach((line) => {
        if (!line.trim()) return;

        const isDeleted = line.includes("*");

        results.push({
          name: line,
          deleted: isDeleted,
        });
      });

      resolve(results);
    });
  });
};

export default analyzeDisk;