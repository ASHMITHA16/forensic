import React, { useState } from "react";
import axios from "axios";
import "./forensic.css";// adjust path to match your project structure

const Upload = () => {
  const [file, setFile] = useState(null);
  const [uploadedPath, setUploadedPath] = useState("");
  const [analysis, setAnalysis] = useState([]);
  const [networkAnalysis, setNetworkAnalysis] = useState([]);
  const [diskAnalysis, setDiskAnalysis] = useState([]);
  const [memoryAnalysis, setMemoryAnalysis] = useState([]);
  const [correlation, setCorrelation] = useState([]);

  // 📁 Select file
  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  // 🚀 Upload file
  const handleUpload = async () => {
    if (!file) {
      alert("Please select a file");
      return;
    }
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await axios.post("http://localhost:5000/api/upload", formData);
      console.log("Uploaded Path:", res.data.data.path);
      setUploadedPath(res.data.data.path);
      alert("File uploaded successfully ✅");
    } catch (err) {
      console.error(err);
      alert("Upload failed ❌");
    }
  };

  // 🔍 Log Analysis
  const handleLogAnalysis = async () => {
    if (!uploadedPath) { alert("Upload file first!"); return; }
    try {
      const res = await axios.post("http://localhost:5000/api/analyze/log", { filePath: uploadedPath });
      setAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Log analysis failed ❌");
    }
  };

  // 🌐 Network Analysis
  const handleNetworkAnalysis = async () => {
    if (!uploadedPath) { alert("Upload file first!"); return; }
    try {
      const res = await axios.post("http://localhost:5000/api/analyze/network", { filePath: uploadedPath });
      setNetworkAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Network analysis failed ❌");
    }
  };

  // 💾 Disk Analysis
  const handleDiskAnalysis = async () => {
    if (!uploadedPath) { alert("Upload file first!"); return; }
    try {
      const res = await axios.post("http://localhost:5000/api/analyze/disk", { filePath: uploadedPath });
      setDiskAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Disk analysis failed ❌");
    }
  };

  // 🧠 Memory Analysis
  const handleMemoryAnalysis = async () => {
    if (!uploadedPath) { alert("Upload file first!"); return; }
    try {
      const res = await axios.post("http://localhost:5000/api/analyze/memory", { filePath: uploadedPath });
      setMemoryAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Memory analysis failed ❌");
    }
  };

  // 🔥 Correlation
  const handleCorrelation = async () => {
    const res = await axios.post("http://localhost:5000/api/analyze/correlate", {
      logData: analysis,
      networkData: networkAnalysis,
      memoryData: memoryAnalysis,
      diskData: diskAnalysis,
    });
    setCorrelation(res.data.data);
  };

  return (
    <div className="forensic-wrapper">

      {/* HEADER */}
      <div className="forensic-header">
        <h2>// Digital Forensic Upload</h2>
      </div>

      {/* UPLOAD PANEL */}
      <div className="upload-panel">
        <div className="file-input-wrapper">
          <input type="file" onChange={handleFileChange} />
        </div>
        <div className="btn-group">
          <button className="btn btn-primary" onClick={handleUpload}>Upload File</button>
          <button className="btn btn-ghost" onClick={handleDiskAnalysis}>Analyze Disk</button>
          <button className="btn btn-ghost" onClick={handleLogAnalysis}>Analyze Logs</button>
          <button className="btn btn-ghost" onClick={handleNetworkAnalysis}>Analyze Network</button>
          <button className="btn btn-ghost" onClick={handleMemoryAnalysis}>Analyze Memory</button>
          <button className="btn btn-danger" onClick={handleCorrelation}>🔥 Run Correlation</button>
        </div>
      </div>

      {/* LOG RESULTS */}
      <div className="result-section">
        <div className="section-title">📊 Log Analysis</div>
        {analysis.length === 0
          ? <p className="result-empty">— no log issues found —</p>
          : analysis.map((item, index) => (
            <div key={index} className="forensic-card">
              <p><strong>Type:</strong> {item.type}</p>
              <p><strong>IP:</strong> {item.ip}</p>
              <p><strong>Details:</strong> {item.line}</p>
            </div>
          ))}
      </div>

      {/* NETWORK RESULTS */}
      <div className="result-section">
        <div className="section-title">🌐 Network Analysis</div>
        {networkAnalysis.length === 0
          ? <p className="result-empty">— no network issues found —</p>
          : networkAnalysis.map((item, index) => (
            <div key={index} className="forensic-card network">
              <h4>{item.type}</h4>
              <p><strong>IP:</strong> {item.ip}</p>
              <p>{item.detail}</p>
            </div>
          ))}
      </div>

      {/* DISK RESULTS */}
      <div className="result-section">
        <div className="section-title">💾 Disk Analysis</div>
        {diskAnalysis.length === 0
          ? <p className="result-empty">— no disk data found —</p>
          : diskAnalysis.map((item, index) => (
            <div key={index} className={`forensic-card ${item.deleted ? "disk-deleted" : "disk-ok"}`}>
              <p>{item.name}</p>
              {item.deleted && <span className="badge-deleted">⚠ Deleted File</span>}
            </div>
          ))}
      </div>

      {/* MEMORY RESULTS */}
      <div className="result-section">
        <div className="section-title">🧠 Memory Analysis</div>
        {memoryAnalysis.length === 0
          ? <p className="result-empty">— no memory issues found —</p>
          : memoryAnalysis.map((item, index) => (
            <div key={index} className={`forensic-card ${item.type === "Suspicious Process" ? "mem-suspicious" : "mem-ok"}`}>
              <p>{item.process}</p>
              <strong>{item.type}</strong>
            </div>
          ))}
      </div>

      {/* CORRELATION RESULTS */}
      <div className="result-section">
        <div className="section-title">🔥 Correlation Results</div>
        {correlation.length === 0
          ? <p className="result-empty">— run correlation to see results —</p>
          : correlation.map((item, index) => (
            <div key={index} className="forensic-card correlation">
              <strong>{item.type}</strong>
              <p>{item.message}</p>
            </div>
          ))}
      </div>

    </div>
  );
};

export default Upload;
