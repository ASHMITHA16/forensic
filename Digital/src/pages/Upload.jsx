import React, { useState } from "react";
import axios from "axios";

const Upload = () => {
  const [file, setFile] = useState(null);
  const [uploadedPath, setUploadedPath] = useState("");
  const [analysis, setAnalysis] = useState([]);
  const [networkAnalysis, setNetworkAnalysis] = useState([]);
  const [diskAnalysis, setDiskAnalysis] = useState([]);

  const styles = {
    card: {
      background: "#0a0f1f",
      border: "1px solid #00f2ff",
      padding: "10px",
      borderRadius: "8px",
      marginBottom: "10px",
      color: "white",
    },
  };

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
      const res = await axios.post(
        "http://localhost:5000/api/upload",
        formData
      );

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
    if (!uploadedPath) {
      alert("Upload file first!");
      return;
    }

    try {
      const res = await axios.post(
        "http://localhost:5000/api/analyze/log",
        { filePath: uploadedPath }
      );

      console.log("Log results:", res.data.data);
      setAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Log analysis failed ❌");
    }
  };

  // 🌐 Network Analysis
  const handleNetworkAnalysis = async () => {
    if (!uploadedPath) {
      alert("Upload file first!");
      return;
    }

    try {
      const res = await axios.post(
        "http://localhost:5000/api/analyze/network",
        { filePath: uploadedPath }
      );

      console.log("Network results:", res.data.data);
      setNetworkAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Network analysis failed ❌");
    }
  };

  // 💾 Disk Analysis
  const handleDiskAnalysis = async () => {
    if (!uploadedPath) {
      alert("Upload file first!");
      return;
    }

    try {
      const res = await axios.post(
        "http://localhost:5000/api/analyze/disk",
        { filePath: uploadedPath }
      );

      console.log("Disk results:", res.data.data);
      setDiskAnalysis(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Disk analysis failed ❌");
    }
  };

  return (
    <div style={{ padding: "20px" }}>
      <h2>🔍 Digital Forensic Upload</h2>

      <input type="file" onChange={handleFileChange} />

      <br /><br />

      <button onClick={handleUpload}>Upload File</button>
      <button onClick={handleDiskAnalysis}>Analyze Disk</button>
      <button onClick={handleLogAnalysis}>Analyze Logs</button>
      <button onClick={handleNetworkAnalysis}>Analyze Network</button>

      {/* LOG RESULTS */}
      <div>
        <h3>📊 Log Analysis</h3>
        {analysis.length === 0 && <p>No log issues found</p>}
        {analysis.map((item, index) => (
          <div key={index} style={styles.card}>
            <p><strong>Type:</strong> {item.type}</p>
            <p><strong>IP:</strong> {item.ip}</p>
            <p><strong>Details:</strong> {item.line}</p>
          </div>
        ))}
      </div>

      {/* NETWORK RESULTS */}
      <div>
        <h3>🌐 Network Analysis</h3>
        {networkAnalysis.length === 0 && <p>No network issues found</p>}
        {networkAnalysis.map((item, index) => (
          <div
            key={index}
            style={{
              border: "1px solid cyan",
              padding: "10px",
              margin: "10px",
            }}
          >
            <h4>{item.type}</h4>
            <p>IP: {item.ip}</p>
            <p>{item.detail}</p>
          </div>
        ))}
      </div>

      {/* DISK RESULTS */}
      <div>
        <h3>💾 Disk Analysis</h3>
        {diskAnalysis.length === 0 && <p>No disk data found</p>}
        {diskAnalysis.map((item, index) => (
          <div
            key={index}
            style={{
              border: item.deleted ? "1px solid red" : "1px solid green",
              padding: "10px",
              margin: "10px",
            }}
          >
            <p>{item.name}</p>
            {item.deleted && <strong>⚠️ Deleted File</strong>}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Upload;