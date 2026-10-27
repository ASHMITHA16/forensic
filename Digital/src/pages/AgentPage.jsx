import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { runMemoryJob, describeMemoryProgress } from "./memoryJob";

const AGENT_CONFIG = {
  disk: {
    icon: "💾",
    title: "Disk Agent",
    endpoint: "/api/analyze/disk",
    result: "/result/disk",
    color: "#22d3a7",
  },
  log: {
    icon: "📊",
    title: "Log Agent",
    endpoint: "/api/analyze/log",
    result: "/result/log",
    color: "#38bdf8",
    description: "Normalize system events, identify attack indicators, and prepare evidence for cross-agent correlation.",
    coverage: ["Authentication failures", "Unauthorized access", "Privilege escalation", "Suspicious commands", "Malware indicators", "IPv4 indicators"],
  },
  memory: {
    icon: "🧠",
    title: "Memory Agent",
    endpoint: "/api/analyze/memory",
    result: "/result/memory",
    color: "#818cf8",
    description: "Seal the dump (SHA-256 chain of custody), run Volatility 3, normalise plugin output, apply the 17-rule detection pack, and re-verify the evidence afterwards.",
    coverage: ["Hidden / orphaned processes", "Code injection (malfind)", "Unlinked modules", "Encoded PowerShell", "Suspicious network sockets", "Rogue services"],
  },
  network: {
    icon: "🌐",
    title: "Network Agent",
    endpoint: "/api/analyze/network",
    result: "/result/network",
    color: "#f43f5e",
  },
};

const AgentPage = ({ type }) => {
  const config = AGENT_CONFIG[type];
  const navigate = useNavigate();

  const [file, setFile] = useState(null);
  const [uploadedPath, setUploadedPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState("idle");
  const [memoryJob, setMemoryJob] = useState(null);

  const acceptedTypes = {
    disk: ".img,.dd,.ad1,.raw",
    log: ".txt,.log",
    memory: ".raw,.mem,.dmp,.vmem,.lime",
    network: ".pcap,.pcapng",
  };

  const storeMemoryResult = (res, fileLabel) => {
    sessionStorage.setItem("result_memory", JSON.stringify(res.data.data));
    sessionStorage.setItem("result_memory_file", fileLabel);
    sessionStorage.setItem("result_memory_meta", JSON.stringify(res.data.meta || {}));
    if (res.data.analysisId) {
      sessionStorage.setItem("result_memory_id", String(res.data.analysisId));
    }
  };

  const memoryErrorMessage = (err) =>
    err.response?.data?.error
      ? `Memory analysis failed ❌\n\n${err.response.data.error}`
      : "Memory analysis failed ❌";

  // Demo: replays the bundled Volatility output through the memory agent pipeline
  const handleMemoryDemo = async () => {
    setLoading(true);
    setPhase("analyzing");
    sessionStorage.removeItem("result_memory_meta");
    sessionStorage.removeItem("result_memory_id");

    try {
      const res = await axios.post("http://localhost:5000/api/analyze/memory/demo");
      storeMemoryResult(res, "demo-replay (windows_case fixtures)");
      navigate(config.result);
    } catch (err) {
      console.error(err);
      alert(memoryErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };


  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];

    if (!selectedFile) return;

    const ext =
      "." + selectedFile.name.split(".").pop().toLowerCase();

    const allowed = acceptedTypes[type]?.split(",");

    if (!allowed.includes(ext)) {
      alert(`Please upload a valid file for ${config.title}`);
      return;
    }

    setFile(selectedFile);
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    setLoading(true);
    setPhase("uploading");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(
        "http://localhost:5000/api/upload",
        formData
      );

      setUploadedPath(res.data.data.path);
      setPhase("idle");
    } catch (err) {
      console.error(err);
      alert("Upload failed ❌");
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async () => {
  if (!uploadedPath) {
    alert("Upload a file first!");
    return;
  }

  setLoading(true);
  setPhase("analyzing");

  // Clear old data
  if (type === "log") {
    sessionStorage.removeItem("result_log_meta");
    sessionStorage.removeItem("result_log_id");
  }

  if (type === "disk") {
    sessionStorage.removeItem("result_disk_meta");
    sessionStorage.removeItem("result_disk_id");
  }

  if (type === "network") {
    sessionStorage.removeItem("result_network_meta");
    sessionStorage.removeItem("result_network_id");
  }

  if (type === "memory") {
    sessionStorage.removeItem("result_memory_meta");
    sessionStorage.removeItem("result_memory_id");
    setMemoryJob(null);
  }

  try {
    // Memory runs as a background job: a real dump outlasts a single HTTP request
    const res = type === "memory"
      ? { data: await runMemoryJob(uploadedPath, setMemoryJob) }
      : await axios.post(
          `http://localhost:5000${config.endpoint}`,
          {
            filePath: uploadedPath,
          }
        );

    // Store findings
    sessionStorage.setItem(
      `result_${type}`,
      JSON.stringify(res.data.data)
    );

    sessionStorage.setItem(
      `result_${type}_file`,
      file?.name || "unknown"
    );

    // Log Agent
    if (type === "log" && res.data.meta) {
      sessionStorage.setItem(
        "result_log_meta",
        JSON.stringify(res.data.meta)
      );

      if (res.data.analysisId) {
        sessionStorage.setItem(
          "result_log_id",
          String(res.data.analysisId)
        );
      }
    }

    // Disk Agent
    if (type === "disk" && res.data.meta) {
      sessionStorage.setItem(
        "result_disk_meta",
        JSON.stringify(res.data.meta)
      );

      if (res.data.analysisId) {
        sessionStorage.setItem(
          "result_disk_id",
          String(res.data.analysisId)
        );
      }
    }

    // Network Agent
    if (type === "network" && res.data.meta) {
      sessionStorage.setItem(
        "result_network_meta",
        JSON.stringify(res.data.meta)
      );

      if (res.data.analysisId) {
        sessionStorage.setItem(
          "result_network_id",
          String(res.data.analysisId)
        );
      }
    }

    // Memory Agent
    if (type === "memory") {
      storeMemoryResult(res, file?.name || "unknown");
    }

    navigate(config.result);
  } catch (err) {
    console.error(err);
    alert(type === "memory" ? memoryErrorMessage(err) : "Analysis failed ❌");
  } finally {
    setLoading(false);
  }
};


  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">
            {config.icon} {config.title}
          </div>

          <div className="page-subtitle">
            Upload and analyze forensic evidence
          </div>
        </div>
      </div>

      <div className="page-body">
        <div className="upload-panel">
          <div className="panel-label">
            Step 1 — Select evidence file
          </div>

          <label className="file-drop-zone">
            <input
              type="file"
              accept={acceptedTypes[type]}
              onChange={handleFileChange}
            />

            <span style={{ fontSize: "1.5rem" }}>📁</span>

            <div>
              {file ? (
                <div className="file-selected-name">
                  ✔ {file.name}
                </div>
              ) : (
                <div className="file-drop-label">
                  Drop file here or <span>click to browse</span>
                </div>
              )}
            </div>
          </label>

          <div className="btn-group">
            <button
              className="btn btn-ghost"
              onClick={handleUpload}
              disabled={loading || !file}
            >
              {phase === "uploading"
                ? "Uploading…"
                : "Upload File"}
            </button>

            <button
              className="btn btn-primary"
              onClick={handleAnalyze}
              disabled={loading || !uploadedPath}
            >
              {phase === "analyzing"
                ? "Analyzing…"
                : `Run ${config.title}`}
            </button>

            {type === "memory" && (
              <button
                className="btn btn-ghost"
                onClick={handleMemoryDemo}
                disabled={loading}
                title="Runs the detection pipeline on bundled Volatility output — no memory image is read"
              >
                Run Demo Case
              </button>
            )}
          </div>

          {loading && (
            <div style={{ marginTop: "16px" }}>
              <div className="loading-bar" />

              <div className="loading-text">
                {phase === "uploading"
                  ? "Uploading file to server…"
                  : type === "memory" && uploadedPath
                  ? describeMemoryProgress(memoryJob)
                  : `Running ${config.title}...`}
              </div>
            </div>
          )}

          {uploadedPath && (
            <div style={{ marginTop: "14px" }}>
              <span
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: "0.68rem",
                  color: "var(--success)",
                  letterSpacing: "0.06em",
                }}
              >
                ✔ FILE READY — {uploadedPath}
              </span>
            </div>
          )}
        </div>

        {(type === "log" || type === "memory") && (
          <div className="log-agent-guide">
            <div className="section-title">📡 Detection coverage</div>
            <p>{config.description}</p>
            <div className="log-coverage-list">
              {config.coverage.map((item) => <span key={item}>{item}</span>)}
            </div>
          </div>
        )}

        <div className="section-title">
          ℹ About This Agent
        </div>

        <div className="summary-box">
          <div className="summary-meta">
            <div className="meta-item">
              <div className="meta-key">Agent Type</div>
              <div className="meta-val">
                {config.title}
              </div>
            </div>

            <div className="meta-item">
              <div className="meta-key">Endpoint</div>

              <div
                className="meta-val"
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: "0.8rem",
                }}
              >
                POST {config.endpoint}
              </div>
            </div>

            <div className="meta-item">
              <div className="meta-key">Output</div>

              <div className="meta-val">
                Structured findings + risk assessment
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default AgentPage;