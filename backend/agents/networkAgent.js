import { exec } from "child_process";

const analyzeNetwork = (filePath) => {
  return new Promise((resolve, reject) => {
 const command = `"C:\\Program Files\\Wireshark\\tshark.exe" -r ${filePath} -Y ip -T fields -e ip.src -e ip.dst`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error.message);
        return;
      }

      const lines = stdout.split("\n");
      const results = [];
      const ipCount = {};

      lines.forEach((line) => {
        if (!line.trim()) return;

        const [src, dst] = line.split("\t");

        if (!src || !dst) return;

        ipCount[dst] = (ipCount[dst] || 0) + 1;

        // Suspicious repeated connections
        if (ipCount[dst] > 5) {
          results.push({
            type: "Suspicious Traffic",
            ip: dst,
            detail: `Multiple packets from ${src}`,
          });
        }

        // External IP detection
        if (!dst.startsWith("192") && !dst.startsWith("10")) {
          results.push({
            type: "External Connection",
            ip: dst,
            detail: `Connection from ${src}`,
          });
        }
      });

      resolve(results);
    });
  });
};

export default analyzeNetwork;