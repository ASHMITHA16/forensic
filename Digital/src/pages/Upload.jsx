import React, { useState } from "react";
import axios from "axios";

const Upload = () => {
    const [file, setFile] = useState(null);
    const [uploadedPath, setUploadedPath] = useState("");
    const [analysis, setAnalysis] = useState([]);
    const[networkAnalysis, setNetworkAnalysis] = useState([]);
    const styles = {
     card: {
     background: "#0a0f1f",
     border: "1px solid #00f2ff",
     padding: "10px",
     borderRadius: "8px",
     marginBottom: "10px",
     color: "white"
   }
};
    // 📁 Handle file select
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

            console.log("Data" ,res.data.data.path);

            setUploadedPath(res.data.data.path);
            alert("File uploaded successfully ✅");
        } catch (err) {
            console.error(err);
            alert("Upload failed ❌");
        }
    };

    const handleLogAnalysis = async () => {
    if (!uploadedPath) {
        alert("Upload file first!");
        return;
    }
     console.log("Analyzing logs at:", uploadedPath);
    try {
        const res = await axios.post(
            "http://localhost:5000/api/analyze/log",
            {
                filePath: uploadedPath
            }
            
        );
       
        setAnalysis(res.data.data);

    } catch (err) {
        console.error(err);
        console.error("Log analysis error:", err.response ? err.response.data : err);
        alert("Log analysis failed ❌");
    }
};
   
    const handleNetworkAnalysis = async () => {
    if (!uploadedPath) {
        alert("Upload file first!");
        return;
    }   
        console.log("Analyzing network data at:", uploadedPath);
    try {
        const res = await axios.post(
            "http://localhost:5000/api/analyze/network",
            {
                filePath: uploadedPath
            }
        );
       
       console.log("Network analysis results:", res.data.data);
        setNetworkAnalysis(res.data.data);
       
    } catch (err) {
        console.error(err);
        console.log("Network analysis error:", err.response ? err.response.data : err);
       
        alert("Network analysis failed ❌");
    }
};

//     const handleAnalyze = async () => {
//         console.log("Analyzing file at:", uploadedPath);
//     if (!uploadedPath) {
//         alert("Upload file first!");
//         return;
//     }

//     try {
//         const res = await axios.post(
//             "http://localhost:5000/api/analyze/disk",
//             {
//                 filePath: uploadedPath
//             }
//         );

       

//         // 🔥 Set analysis data
//         setAnalysis(res.data.data);
//         console.log("Analysis results:", res.data.data);
//     } catch (err) {
//         console.error(err);
//         alert("Analysis failed ❌");
//     }
// };

    // 🔍 Analyze file
   
    return (
        <div style={{ padding: "20px" }}>
            <h2>🔍 Digital Forensic Upload</h2>

            <input type="file" onChange={handleFileChange} />

            <br /><br />

            <button onClick={handleUpload}>
                Upload File
            </button>
             {/* <button onClick={handleAnalyze}>
                Analyze Disk
            </button> */}
            <button onClick={handleLogAnalysis}>
             Analyze Logs
            </button>
            <button onClick={handleNetworkAnalysis}>    
                Analyze Network
            </button>

           <div>
            <h3>📊 Analysis Results</h3>

            {analysis.map((item, index) => (
           <div key={index} style={styles.card}>
           <p><strong>Type:</strong> {item.type}</p>
           <p><strong>IP:</strong> {item.ip}</p>
           <p><strong>Details:</strong> {item.line}</p>
           </div>
          ))}
         </div>
         <div>
        <h3>Network Analysis</h3>

           {Array.isArray(networkAnalysis) &&
             networkAnalysis.map((item, index) => (
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
        </div>
    );
};

export default Upload;