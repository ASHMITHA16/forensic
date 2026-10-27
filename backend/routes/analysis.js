import express from "express";
import fs from "fs";
import analyzeDisk from "../agents/diskAgent.js";
import analyzeLogs from "../agents/logAgent.js";
import analyzeNetwork from "../agents/networkAgent.js";
import analyzeMemory, { replayMemoryDemo, startMemoryJob, getMemoryJob } from "../agents/memoryAgent.js";
import correlate from "../agents/correlationAgent.js";
import { generateHash } from "../services/hashService.js";
import Evidence from "../models/Evidence.js";
import History from "../models/History.js";
import generateReport, { generatePdf } from "../agents/reportAgent.js";
import generateNReport, { generatePdf as generateNPdf } from "../agents/report.js";

const router = express.Router();
// 🔐 Integrity Check Function
const verifyIntegrity = async (filePath) => {
  const evidence = await Evidence.findOne({ path: filePath });

  if (!evidence) {
    throw new Error("Evidence not found");
  }

  const newHash = await generateHash(filePath);

  return {
    isTampered: evidence.hash !== newHash,
    originalHash: evidence.hash,
    currentHash: newHash
  };
};

router.post("/analyze/log", async (req, res) => {
  try {
    const { filePath } = req.body;

    // 🔐 CHECK INTEGRITY
    const integrity = await verifyIntegrity(filePath);
    if (integrity.isTampered) {
      return res.status(400).json({
        message: "⚠️ File tampered. Cannot analyze.",
        integrity
      });
    }

    const analysis = await analyzeLogs(filePath);

    const savedAnalysis = await History.create({
      agent: "log",
      fileName: filePath.split(/[/\\]/).pop(),
      findings: analysis.findings.length,
      risk: analysis.meta.risk.toLowerCase(),
      results: analysis.findings,
      analysisMeta: analysis.meta,
      evidenceHash: integrity.currentHash,
    });

    res.json({
      message: "Log analysis completed",
      analysisId: savedAnalysis._id,
      data: analysis.findings,
      meta: analysis.meta
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/analyze/log/report", async (req, res) => {
  try {
    const { findings = [], meta = {}, fileName = "log-evidence" } = req.body;
    const report = generateReport({ findings, meta }, fileName);
    const format = req.query.format || "json";

    if (format === "markdown") {
      res.type("text/markdown").send(report.markdown);
    } else if (format === "pdf") {
      const pdf = await generatePdf(report);
      res.type("application/pdf").send(pdf);
    } else {
      res.json(report.json);
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get("/analyze/log/report/:analysisId", async (req, res) => {
  try {
    const savedAnalysis = await History.findOne({ _id: req.params.analysisId, agent: "log" });
    if (!savedAnalysis) return res.status(404).json({ error: "Log analysis not found" });

    const report = generateReport({ findings: savedAnalysis.results, meta: savedAnalysis.analysisMeta }, savedAnalysis.fileName);
    const format = req.query.format || "json";
    if (format === "markdown") return res.type("text/markdown").send(report.markdown);
    if (format === "pdf") return res.type("application/pdf").send(await generatePdf(report));
    return res.json(report.json);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});


// Integrity check → memory agent → History. Shared by the sync and job paths.
const runMemoryAnalysis = async (filePath, caseId) => {
  const integrity = await verifyIntegrity(filePath);
  if (integrity.isTampered) {
    const err = new Error("⚠️ File tampered. Cannot analyze.");
    err.status = 400;
    err.integrity = integrity;
    throw err;
  }

  const analysis = await analyzeMemory(filePath, { caseId });

  const savedAnalysis = await History.create({
    agent: "memory",
    fileName: filePath.split(/[/\\]/).pop(),
    findings: analysis.findings.length,
    risk: analysis.meta.risk.toLowerCase(),
    results: analysis.findings,
    analysisMeta: analysis.meta,
    evidenceHash: integrity.currentHash,
  });

  return {
    message: "Memory analysis completed",
    analysisId: savedAnalysis._id,
    data: analysis.findings,
    meta: analysis.meta,
  };
};

// { filePath, async: true } → 202 { jobId }; poll GET /analyze/memory/jobs/:jobId.
// Without `async` the request waits for the result (fine for small images only).
router.post("/analyze/memory", async (req, res) => {
  const { filePath, async: runAsync } = req.body;

  if (!filePath) {
    return res.status(400).json({ error: "filePath is required" });
  }

  if (runAsync) {
    const job = startMemoryJob(filePath, (caseId) => runMemoryAnalysis(filePath, caseId));
    return res.status(202).json({ message: "Memory analysis started", jobId: job.id });
  }

  try {
    res.json(await runMemoryAnalysis(filePath));
  } catch (err) {
    if (err.integrity) {
      return res.status(400).json({ message: err.message, integrity: err.integrity });
    }
    res.status(err.status || 500).json({ error: err.message, code: err.code || null });
  }
});

router.get("/analyze/memory/jobs/:jobId", (req, res) => {
  const job = getMemoryJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: "Memory analysis job not found (the server may have restarted)" });
  res.json(job);
});

// Demo: replays the bundled Volatility plugin output — no memory image is read
router.post("/analyze/memory/demo", async (req, res) => {
  try {
    const analysis = await replayMemoryDemo();

    const savedAnalysis = await History.create({
      agent: "memory",
      fileName: "demo-replay (windows_case fixtures)",
      findings: analysis.findings.length,
      risk: analysis.meta.risk.toLowerCase(),
      results: analysis.findings,
      analysisMeta: analysis.meta,
    });

    res.json({
      message: "Memory demo replay completed",
      analysisId: savedAnalysis._id,
      data: analysis.findings,
      meta: analysis.meta,
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message, code: err.code || null });
  }
});

// Full memory agent output envelope (memory_agent_output.json) for a saved run
router.get("/analyze/memory/envelope/:analysisId", async (req, res) => {
  try {
    const savedAnalysis = await History.findOne({ _id: req.params.analysisId, agent: "memory" });
    const envelopePath = savedAnalysis?.analysisMeta?.envelopePath;
    if (!envelopePath || !fs.existsSync(envelopePath)) {
      return res.status(404).json({ error: "Memory envelope not found" });
    }
    return res.type("application/json").sendFile(envelopePath);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

router.post("/analyze/disk", async (req, res) => {
  try {
    const { filePath } = req.body;

    const integrity = await verifyIntegrity(filePath);
    if (integrity.isTampered) {
      return res.status(400).json({
        message: "⚠️ File tampered. Cannot analyze.",
        integrity
      });
    }

    const analysis = await analyzeDisk(filePath);

    const savedAnalysis = await History.create({
      agent: "disk",
      fileName: filePath.split(/[/\\]/).pop(),
      findings: analysis.findings.length,
      risk: analysis.meta.risk.toLowerCase(),
      results: analysis.findings,
      analysisMeta: analysis.meta,
      evidenceHash: integrity.currentHash,
    });

    res.json({
      message: "Disk analysis completed",
      analysisId: savedAnalysis._id,
      data: analysis.findings,
      meta: analysis.meta,
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/analyze/network/report", async (req, res) => {
  try {
    const { findings = [], meta = {}, fileName = "network-evidence" } = req.body;
    const report = generateNReport(
      { findings, meta: { ...meta, agent: "network" } },
      fileName
    );
    const format = req.query.format || "json";

    if (format === "markdown") {
      return res.type("text/markdown").send(report.markdown);
    }

    if (format === "pdf") {
      const pdf = await generateNPdf(report);
      return res.type("application/pdf").send(pdf);
    }

    return res.json(report.json);

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get("/analyze/network/report/:analysisId", async (req, res) => {

  try {

    const savedAnalysis =
      await History.findOne({
        _id: req.params.analysisId,
        agent: "network"
      });

    if (!savedAnalysis) {
      return res.status(404).json({
        error: "Network analysis not found"
      });
    }

   const report = generateNReport(
  {
    findings: savedAnalysis.results,
    meta: {
      risk: savedAnalysis.risk,
      agent: "network"
    }
  },
  savedAnalysis.fileName
);

    const format = req.query.format || "json";

    if (format === "markdown") {
      return res.type("text/markdown").send(report.markdown);
    }

    if (format === "pdf") {
      return res
        .type("application/pdf")
        .send(await generateNPdf(report));
    }

    return res.json(report.json);

  } catch (err) {

    return res.status(400).json({
      error: err.message
    });

  }

});

router.post("/analyze/network", async (req, res) => {
  try {
    const { filePath } = req.body;

    const integrity = await verifyIntegrity(filePath);
    if (integrity.isTampered) {
      return res.status(400).json({
        message: "⚠️ File tampered. Cannot analyze.",
        integrity
      });
    }

     const result = await analyzeNetwork(filePath);
     const hasMaliciousIP = result.some(
  r => r.type === "Known Malicious IP"
);

const hasPortScan = result.some(
  r => r.type === "Potential Port Scan"
);

const hasBeaconing = result.some(
  r => r.type === "Beaconing Activity"
);

let risk = "low";

if (hasMaliciousIP) {
  risk = "high";
}
else if (hasPortScan || hasBeaconing) {
  risk = "medium";
}
else if (result.length > 20) {
  risk = "medium";
}
console.log(`Network analysis risk level: ${risk}`);
    const savedAnalysis = await History.create({
  agent: "network",
  fileName: filePath.split(/[\/\\]/).pop(), 
  findings: result.length,
  risk,
  results: result
});

   res.json({
  message: "Analysis completed",
  analysisId: savedAnalysis._id,
  data: result,
  meta: {
    totalPackets: result.length,

    maliciousIPs: result.filter(
      r => r.type === "Known Malicious IP"
    ).length,

    portScans: result.filter(
      r => r.type === "Potential Port Scan"
    ).length,

    beaconingActivities: result.filter(
      r => r.type === "Beaconing Activity"
    ).length,

    externalConnections: result.filter(
      r => r.type === "External Connection"
    ).length,

    risk,
    summary: `Detected ${result.length} network findings`
  }
});

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


router.post("/analyze/correlate", async (req, res) => {
  const { logData, networkData, memoryData, diskData } = req.body;

  const result = correlate({ logData, networkData, memoryData, diskData });

  res.json({ data: result });
});


export default router;