import { exec } from "child_process";

const maliciousIPs = [
  "185.220.101.1",
  "45.33.32.156",
  "103.21.244.0",
];

const analyzeNetwork = (filePath) => {
  return new Promise((resolve, reject) => {

    const command =
      `"C:\\Program Files\\Wireshark\\tshark.exe" ` +
      `-r "${filePath}" ` +
      `-T fields ` +
      `-e ip.src -e ip.dst -e tcp.dstport`;

    exec(command, (error, stdout, stderr) => {

      if (error) {
        console.log("TSHARK ERROR:", error);
        console.log(stderr);
        reject(error);
        return;
      }

      const lines = stdout.split("\n");

      const results = [];

      const ipCount = {};
      const portMap = {};

      lines.forEach((line) => {

        if (!line.trim()) return;

        const [src, dst, port] = line.split("\t");

        if (!src || !dst) return;

        // -------------------------
        // Count packets per destination
        // -------------------------
        ipCount[dst] = (ipCount[dst] || 0) + 1;

        // -------------------------
        // External Connection
        // -------------------------
        if (
          !dst.startsWith("192.168.") &&
          !dst.startsWith("10.") &&
          !dst.startsWith("172.")
        ) {
          results.push({
            type: "External Connection",
            ip: dst,
            detail: `External communication from ${src}`,
          });
        }

        // -------------------------
        // Known Malicious IP
        // -------------------------
        if (maliciousIPs.includes(dst)) {
          results.push({
            type: "Known Malicious IP",
            ip: dst,
            detail: "Matched threat intelligence list",
          });
        }

        // -------------------------
        // Port Scan Detection
        // -------------------------
        if (port) {

          if (!portMap[src]) {
            portMap[src] = new Set();
          }

          portMap[src].add(port);

          if (portMap[src].size > 10) {
            results.push({
              type: "Potential Port Scan",
              ip: src,
              detail: `Accessed ${portMap[src].size} different ports`,
            });
          }
        }
      });

      // -------------------------
      // Beaconing / Repeated Traffic
      // -------------------------
      Object.entries(ipCount).forEach(([ip, count]) => {

        if (count > 100) {
          results.push({
            type: "Beaconing Activity",
            ip,
            detail: `${count} packets sent to same destination`,
          });
        }

      });

      // Remove duplicates
      const uniqueResults = [];

      const seen = new Set();

      results.forEach((item) => {

        const key = item.type + item.ip;

        if (!seen.has(key)) {
          seen.add(key);
          uniqueResults.push(item);
        }

      });

      resolve(uniqueResults);
    });
  });
};

export default analyzeNetwork;