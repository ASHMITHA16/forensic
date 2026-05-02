import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const AGENT_CONFIG = {
  disk:    { icon: "💾", title: "Disk Agent",     endpoint: "/api/analyze/disk",    result: "/result/disk",    color: "#22d3a7" },
  log:     { icon: "📊", title: "Log Agent",      endpoint: "/api/analyze/log",     result: "/result/log",     color: "#38bdf8" },
  memory:  { icon: "🧠", title: "Memory Agent",   endpoint: "/api/analyze/memory",  result: "/result/memory",  color: "#818cf8" },
  network: { icon: "🌐", title: "Network Agent",  endpoint: "/api/analyze/network", result: "/result/network", color: "#f43f5e" },
};

const AgentPage = ({ type }) => {
  const config = AGENT_CONFIG[type];
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [uploadedPath, setUploadedPath] = useState("");
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState("idle"); // idle | uploading | analyzing

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) { alert("Please select a file first."); return; }
    setLoading(true);
    setPhase("uploading");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post("http://localhost:5000/api/upload", formData);
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
    if (!uploadedPath) { alert("Upload a file first!"); return; }
    setLoading(true);
    setPhase("analyzing");

    try {
      const res = await axios.post(
        `http://localhost:5000${config.endpoint}`,
        { filePath: uploadedPath }
      );
      // Store results in sessionStorage so result page can read them
      sessionStorage.setItem(`result_${type}`, JSON.stringify(res.data.data));
      sessionStorage.setItem(`result_${type}_file`, file?.name || "unknown");
      navigate(config.result);
    } catch (err) {
      console.error(err);
      alert("Analysis failed ❌");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">{config.icon} // {type}_agent</div>
          <div className="page-subtitle">{config.title} · Upload and analyze forensic evidence</div>
        </div>
      </div>

      <div className="page-body">
        <div className="upload-panel">
          <div className="panel-label">Step 1 — Select evidence file</div>
          <label className="file-drop-zone">
            <input type="file" onChange={handleFileChange} />
            <span style={{ fontSize: "1.5rem" }}>📁</span>
            <div>
              {file
                ? <div className="file-selected-name">✔ {file.name}</div>
                : <div className="file-drop-label">Drop file here or <span>click to browse</span></div>
              }
            </div>
          </label>

          <div className="btn-group">
            <button className="btn btn-ghost" onClick={handleUpload} disabled={loading || !file}>
              {phase === "uploading" ? "Uploading…" : "Upload File"}
            </button>
            <button
              className="btn btn-primary"
              onClick={handleAnalyze}
              disabled={loading || !uploadedPath}
            >
              {phase === "analyzing" ? "Analyzing…" : `Run ${config.title}`}
            </button>
          </div>

          {loading && (
            <div style={{ marginTop: "16px" }}>
              <div className="loading-bar" />
              <div className="loading-text">
                {phase === "uploading" ? "Uploading file to server…" : `Running ${type} analysis engine…`}
              </div>
            </div>
          )}

          {uploadedPath && (
            <div style={{ marginTop: "14px" }}>
              <span style={{ fontFamily: "var(--mono)", fontSize: "0.68rem", color: "var(--success)", letterSpacing: "0.06em" }}>
                ✔ FILE READY — {uploadedPath}
              </span>
            </div>
          )}
        </div>

        <div className="section-title">ℹ About This Agent</div>
        <div className="summary-box">
          <div className="summary-meta">
            <div className="meta-item">
              <div className="meta-key">Agent Type</div>
              <div className="meta-val">{config.title}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">Endpoint</div>
              <div className="meta-val" style={{ fontFamily: "var(--mono)", fontSize: "0.8rem" }}>POST {config.endpoint}</div>
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
