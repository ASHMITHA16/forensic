const correlate = (logData, networkData, memoryData, diskData) => {
  const alerts = [];

  // 🔥 Check repeated IP
  const suspiciousIPs = new Set();

  logData.forEach(item => {
    if (item.ip) suspiciousIPs.add(item.ip);
  });

  networkData.forEach(item => {
    if (suspiciousIPs.has(item.ip)) {
      alerts.push({
        type: "Correlated Attack",
        message: `IP ${item.ip} found in logs & network`,
      });
    }
  });

  // 🔥 Check malware in memory
  memoryData.forEach(item => {
    if (item.type === "Suspicious Process") {
      alerts.push({
        type: "Malware Detected",
        message: item.detail,
      });
    }
  });

  // 🔥 Check deleted files
  diskData.forEach(item => {
    if (item.deleted) {
      alerts.push({
        type: "Deleted Evidence",
        message: item.name,
      });
    }
  });

  return alerts;
};

export default correlate;