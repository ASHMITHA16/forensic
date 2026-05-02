import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import "./forensic.css";

import Sidebar   from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import AgentPage from "./pages/AgentPage";
import ResultPage from "./pages/ResultPage";
import History   from "./pages/History";

function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/"               element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard"      element={<Dashboard />} />

            {/* Agent pages */}
            <Route path="/agent/disk"     element={<AgentPage type="disk" />} />
            <Route path="/agent/log"      element={<AgentPage type="log" />} />
            <Route path="/agent/memory"   element={<AgentPage type="memory" />} />
            <Route path="/agent/network"  element={<AgentPage type="network" />} />

            {/* Result pages */}
            <Route path="/result/disk"    element={<ResultPage type="disk" />} />
            <Route path="/result/log"     element={<ResultPage type="log" />} />
            <Route path="/result/memory"  element={<ResultPage type="memory" />} />
            <Route path="/result/network" element={<ResultPage type="network" />} />

            {/* History */}
            <Route path="/history"        element={<History />} />

            {/* Fallback */}
            <Route path="*"              element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
