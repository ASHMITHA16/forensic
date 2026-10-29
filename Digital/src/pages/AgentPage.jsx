import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { runMemoryJob, describeMemoryProgress } from "./memoryJob";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

const AGENT_CONFIG = {
  disk: {
    icon: "disk",
    title: "Disk Agent",
    endpoint: "/api/analyze/disk",
    result: "/result/disk",
    color: "#22d3a7",
  },
  log: {
    icon: "log",
    title: "Log Agent",
    endpoint: "/api/analyze/log",
    result: "/result/log",
    color: "#38bdf8",
    description: "Normalize system events, identify attack indicators, and prepare evidence for cross-agent correlation.",
    coverage: ["Authentication failures", "Unauthorized access", "Privilege escalation", "Suspicious commands", "Malware indicators", "IPv4 indicators"],
  },
  memory: {
    icon: "memory",
    title: "Memory Agent",
    endpoint: "/api/analyze/memory",
    result: "/result/memory",
    color: "#818cf8",
    description: "Seal the dump (SHA-256 chain of custody), run Volatility 3, normalise plugin output, apply the 17-rule detection pack, and re-verify the evidence afterwards.",
    coverage: ["Hidden / orphaned processes", "Code injection (malfind)", "Unlinked modules", "Encoded PowerShell", "Suspicious network sockets", "Rogue services"],
  },
  network: {
    icon: "network",
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
  const [uploadPercent, setUploadPercent] = useState(0);
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
    // A new file invalidates the previous upload; otherwise Run would analyze the old one
    setUploadedPath("");
  };

  // Uploads the selected file and returns its server path (null on failure)
  const uploadFile = async () => {
    setPhase("uploading");
    setUploadPercent(0);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(
        "http://localhost:5000/api/upload",
        formData,
        {
          // Memory/disk images are GBs; show how far along the transfer is
          onUploadProgress: (e) => e.total && setUploadPercent(Math.round((e.loaded / e.total) * 100)),
        }
      );

      setUploadedPath(res.data.data.path);
      setPhase("idle");
      return res.data.data.path;
    } catch (err) {
      console.error(err);
      setPhase("idle");
      alert(err.response?.data?.error ? `Upload failed ❌\n\n${err.response.data.error}` : "Upload failed ❌");
      return null;
    }
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    setLoading(true);
    await uploadFile();
    setLoading(false);
  };

  const handleAnalyze = async () => {
  if (!file && !uploadedPath) {
    alert("Select a file first!");
    return;
  }

  setLoading(true);

  // Run uploads the selected file itself if Upload File was not clicked
  const filePath = uploadedPath || await uploadFile();
  if (!filePath) {
    setLoading(false);
    return;
  }

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
      ? { data: await runMemoryJob(filePath, setMemoryJob) }
      : await axios.post(
          `http://localhost:5000${config.endpoint}`,
          {
            filePath,
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


  const formatSize = (bytes) => {
    if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
    if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
    return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  };

  return (
    <>
      <PageHeader
        icon={config.icon}
        eyebrow="Agent"
        title={config.title}
        subtitle="Upload a piece of evidence and run the agent to produce structured findings."
      />

      <div className="page-body">
        <div className="upload-panel">
          <div className="panel-label">Select evidence file</div>
          <p className="panel-hint">
            Accepted formats: {acceptedTypes[type].split(",").join(", ")}. Running the agent uploads the file automatically.
          </p>

          <label className={`file-drop-zone ${file ? "has-file" : ""}`}>
            <input
              type="file"
              accept={acceptedTypes[type]}
              onChange={handleFileChange}
            />

            <div className="file-drop-icon">
              <Icon name={file ? "check" : "upload"} size={20} />
            </div>

            <div>
              {file ? (
                <>
                  <div className="file-selected-name">{file.name}</div>
                  <div className="file-drop-meta">{formatSize(file.size)} · Click to choose a different file</div>
                </>
              ) : (
                <>
                  <div className="file-drop-label">
                    Choose a file or <span>browse your computer</span>
                  </div>
                  <div className="file-drop-meta">Large disk and memory images can take a few minutes to upload</div>
                </>
              )}
            </div>
          </label>

          <div className="btn-group">
            <button
              className="btn btn-primary"
              onClick={handleAnalyze}
              disabled={loading || (!file && !uploadedPath)}
            >
              {phase === "analyzing"
                ? "Analyzing…"
                : phase === "uploading"
                ? `Uploading… ${uploadPercent}%`
                : `Run ${config.title}`}
            </button>

            <button
              className="btn btn-ghost"
              onClick={handleUpload}
              disabled={loading || !file}
            >
              <Icon name="upload" size={16} />
              {phase === "uploading" ? "Uploading…" : "Upload only"}
            </button>

            {type === "memory" && (
              <button
                className="btn btn-ghost"
                onClick={handleMemoryDemo}
                disabled={loading}
                title="Runs the detection pipeline on bundled Volatility output — no memory image is read"
              >
                Run demo case
              </button>
            )}
          </div>

          {loading && (
            <div className="loading-block">
              <div className="loading-bar" />

              <div className="loading-text">
                {phase === "uploading"
                  ? `Uploading file to server… ${uploadPercent}%`
                  : type === "memory" && phase === "analyzing"
                  ? describeMemoryProgress(memoryJob)
                  : `Running ${config.title}…`}
              </div>
            </div>
          )}

          {uploadedPath && (
            <div className="upload-status">
              <Icon name="check" size={16} />
              File ready on server <code>{uploadedPath}</code>
            </div>
          )}
        </div>

        {(type === "log" || type === "memory") && (
          <div className="log-agent-guide">
            <h2 className="section-title">Detection coverage</h2>
            <p>{config.description}</p>
            <div className="log-coverage-list">
              {config.coverage.map((item) => <span key={item}>{item}</span>)}
            </div>
          </div>
        )}

        <h2 className="section-title">About this agent</h2>

        <div className="summary-box">
          <div className="summary-meta">
            <div className="meta-item">
              <div className="meta-key">Agent type</div>
              <div className="meta-val">{config.title}</div>
            </div>

            <div className="meta-item">
              <div className="meta-key">Endpoint</div>
              <div className="meta-val mono">POST {config.endpoint}</div>
            </div>

            <div className="meta-item">
              <div className="meta-key">Output</div>
              <div className="meta-val">Structured findings + risk assessment</div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default AgentPage;
