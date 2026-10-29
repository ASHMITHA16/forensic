import React, { useEffect, useState } from "react";
import axios from "axios";
import { useLocation } from "react-router-dom";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

const API = "http://localhost:5000/api";

const DOMAINS = [
  { key: "log",     icon: "📊", label: "Log" },
  { key: "network", icon: "🌐", label: "Network" },
  { key: "memory",  icon: "🧠", label: "Memory" },
  { key: "disk",    icon: "💾", label: "Disk" },
];
const DOMAIN_ICON = Object.fromEntries(DOMAINS.map((d) => [d.key, d.icon]));

const pct = (v) => `${Math.round((Number(v) || 0) * 100)}%`;
const admissibleLabel = (v) => (v === true ? "Yes" : v === false ? "NO" : "Not established");

function readStored() {
  try {
    const raw = sessionStorage.getItem("result_correlation");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function storeResult(result) {
  try {
    sessionStorage.setItem("result_correlation", JSON.stringify(result));
  } catch {
    // A very large envelope can exceed sessionStorage; the result is still on screen
  }
}

const sourceOption = (s) =>
  `${s.fileName} · ${new Date(s.createdAt).toLocaleString()} · ${s.findings} finding(s) · ${String(s.risk || "").toUpperCase()}`
  + (s.mode === "replay" ? " · DEMO" : "");

const CorrelationPage = () => {
  const location = useLocation();
  const [sources, setSources] = useState({});
  const [selected, setSelected] = useState({ log: "", network: "", memory: "", disk: "" });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(readStored);
  const [showContext, setShowContext] = useState(false);
  const [openEvidence, setOpenEvidence] = useState({});

  useEffect(() => {
    axios.get(`${API}/analyze/correlate/sources`)
      .then((res) => setSources(res.data.sources || {}))
      .catch((err) => console.error(err));
  }, []);

  // Opened from History: load the saved run
  useEffect(() => {
    const id = location.state?.analysisId;
    if (!id) return;
    axios.get(`${API}/analyze/correlate/${id}`)
      .then((res) => {
        const loaded = { analysisId: res.data.analysisId, data: res.data.data };
        setResult(loaded);
        storeResult(loaded);
      })
      .catch((err) => alert(err.response?.data?.error || "Could not load correlation run ❌"));
  }, [location.state]);

  const selectLatest = () => {
    setSelected(Object.fromEntries(DOMAINS.map((d) => [d.key, sources[d.key]?.[0]?.analysisId || ""])));
  };

  const chosen = Object.entries(selected).filter(([, id]) => id);

  const run = async (demo) => {
    setLoading(true);
    try {
      const res = demo
        ? await axios.post(`${API}/analyze/correlate/demo`)
        : await axios.post(`${API}/analyze/correlate`, { analysisIds: Object.fromEntries(chosen) });
      const next = { analysisId: res.data.analysisId, data: res.data.data, storageError: res.data.storageError };
      setResult(next);
      storeResult(next);
      setOpenEvidence({});
    } catch (err) {
      console.error(err);
      alert(err.response?.data?.error ? `Correlation failed ❌\n\n${err.response.data.error}` : "Correlation failed ❌");
    } finally {
      setLoading(false);
    }
  };

  const download = async (format) => {
    if (!result?.data) return;
    try {
      const res = result.analysisId
        ? await axios.get(`${API}/analyze/correlate/report/${result.analysisId}?format=${format}`, { responseType: "blob" })
        : await axios.post(`${API}/analyze/correlate/report?format=${format}`, result.data, { responseType: "blob" });
      const ext = format === "markdown" ? "md" : format;
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `correlation-report-${result.data.agent?.run_id || "run"}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert("Report download failed ❌");
    }
  };

  const env = result?.data;
  const a = env?.assessment || {};
  const itemsByRef = Object.fromEntries((env?.evidence_items || []).map((i) => [i.ref, i]));
  const timeline = (env?.timeline || []).filter((t) => showContext || t.kind === "finding");

  return (
    <>
      <PageHeader
        icon="correlation"
        eyebrow="Agent"
        title="Correlation Agent"
        subtitle="Link findings across log, network, memory and disk evidence."
      />

      <div className="page-body corr-page">
        <div className="upload-panel">
          <div className="panel-label">Choose the agent runs to correlate</div>
          <div className="corr-select-grid">
            {DOMAINS.map((d) => (
              <label key={d.key} className="corr-select">
                <span><Icon name={d.key} size={16} /> {d.label}</span>
                <select
                  value={selected[d.key]}
                  onChange={(e) => setSelected({ ...selected, [d.key]: e.target.value })}
                >
                  <option value="">— not included —</option>
                  {(sources[d.key] || []).map((s) => (
                    <option key={s.analysisId} value={s.analysisId}>{sourceOption(s)}</option>
                  ))}
                </select>
              </label>
            ))}
          </div>
          <p className="corr-hint">
            Pick runs from the <b>same host and incident</b>. The agent links findings through shared
            addresses, file paths, program names and users; it cannot tell whether two sources came from different machines.
          </p>

          <div className="btn-group">
            <button className="btn btn-ghost" onClick={selectLatest} disabled={loading}>Select latest of each</button>
            <button className="btn btn-primary" onClick={() => run(false)} disabled={loading || chosen.length === 0}>
              {loading ? "Correlating…" : `Run Correlation (${chosen.length} source${chosen.length === 1 ? "" : "s"})`}
            </button>
            <button
              className="btn btn-ghost"
              onClick={() => run(true)}
              disabled={loading}
              title="Correlates bundled log/network/disk fixtures with the memory demo replay — not evidence"
            >
              Run demo case
            </button>
          </div>
          {loading && (
            <div className="loading-block">
              <div className="loading-bar" />
              <div className="loading-text">Normalising findings, linking entities, applying rule pack…</div>
            </div>
          )}
        </div>

        {!env && (
          <div className="log-agent-guide">
            <h2 className="section-title">What it does</h2>
            <p>
              Normalises every agent's findings into evidence items, links them across domains by shared entities,
              applies the COR-v1 rule pack, places only real timestamps on a unified timeline, maps the result to
              an ATT&CK tactic chain and weighs it against the null hypothesis. Every correlation cites the findings
              it rests on and lists the benign explanations still to rule out.
            </p>
            <div className="log-coverage-list">
              {["C2 attribution (memory ↔ network)", "Executable on disk running in memory", "Brute force + scanning source",
                "Logged command ↔ live process", "File in logs ↔ file on disk", "Anti-forensics co-occurrence", "Multi-domain pivot entities"]
                .map((c) => <span key={c}>{c}</span>)}
            </div>
          </div>
        )}

        {env && (
          <>
            {(env.agent?.mode === "demo" || a.admissible === false) && (
              <div className="mem-status-banner">
                <strong>{env.agent?.mode === "demo" ? "DEMO CASE — NOT EVIDENCE" : "INCLUDES NON-ADMISSIBLE EVIDENCE"}</strong>
                <p>
                  {env.agent?.mode === "demo"
                    ? "Bundled fixtures correlated with the memory demo replay. Correlations citing the INVALID memory envelope are flagged and down-weighted."
                    : "At least one source failed its integrity check or is a replay. Correlations citing it are flagged and down-weighted."}
                </p>
              </div>
            )}
            {result.storageError && (
              <div className="mem-status-banner"><strong>NOT SAVED TO HISTORY</strong><p>{result.storageError}</p></div>
            )}

            <h2 className="section-title">Assessment</h2>
            <div className="summary-box">
              <div className="summary-meta">
                <div className="meta-item">
                  <div className="meta-key">Risk</div>
                  <div className="meta-val"><span className={`risk-badge ${String(a.risk_level).toLowerCase()}`}>{a.risk_level}</span> {a.risk_score}/100</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Assessment confidence</div>
                  <div className="meta-val">{pct(a.confidence)}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Correlations</div>
                  <div className="meta-val">{env.correlations.length}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Status</div>
                  <div className="meta-val">{env.agent?.status}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Domains</div>
                  <div className="meta-val">{env.coverage.domains_supplied.map((d) => DOMAIN_ICON[d]).join(" ") || "-"}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Admissible</div>
                  <div className="meta-val">{admissibleLabel(a.admissible)}</div>
                </div>
              </div>
              <p className="log-raw" style={{ marginTop: 14 }}>{env.summary}</p>
              <div className="mem-alternatives">
                <strong>How the risk score was computed</strong>
                <ul>{(a.risk_basis || []).map((b, i) => <li key={i}>{b}</li>)}</ul>
                <strong style={{ marginTop: 8 }}>Confidence basis</strong>
                <ul><li>{a.confidence_basis}</li></ul>
              </div>
              <p className="corr-digest">core digest {env.core_digest}</p>
              <div className="btn-group" style={{ marginTop: 12 }}>
                <button className="btn btn-ghost btn-sm" onClick={() => download("json")}><Icon name="download" size={14} /> JSON</button>
                <button className="btn btn-ghost btn-sm" onClick={() => download("markdown")}><Icon name="download" size={14} /> Markdown</button>
                <button className="btn btn-primary btn-sm" onClick={() => download("pdf")}><Icon name="download" size={14} /> PDF report</button>
                {result.analysisId && env.workspace && (
                  <a className="btn btn-ghost btn-sm" href={`${API}/analyze/correlate/envelope/${result.analysisId}`} target="_blank" rel="noreferrer">
                    <Icon name="download" size={14} /> Full envelope
                  </a>
                )}
              </div>
            </div>

            <h2 className="section-title">Hypotheses</h2>
            <div className="corr-hyp-grid">
              {env.hypotheses.map((h) => (
                <div key={h.hypothesis_id} className={`forensic-card ${h.hypothesis_id === "H1" ? "correlation" : ""}`}>
                  <div className="log-finding-header">
                    <strong>{h.hypothesis_id}</strong>
                    <span className="severity-chip info">{pct(h.confidence)}</span>
                  </div>
                  <p className="log-explanation">{h.statement}</p>
                  <p className="log-raw">{h.confidence_basis}</p>
                  {h.supporting.length > 0 && (
                    <div className="mem-alternatives"><strong>Supports</strong><ul>{h.supporting.map((s, i) => <li key={i}>{s}</li>)}</ul></div>
                  )}
                  {h.weakening.length > 0 && (
                    <div className="mem-alternatives"><strong>Weakens</strong><ul>{h.weakening.map((s, i) => <li key={i}>{s}</li>)}</ul></div>
                  )}
                </div>
              ))}
            </div>

            <h2 className="section-title">Attack chain</h2>
            <div className="summary-box">
              <div className="corr-chain">
                {env.attack_chain.phases.map((p, i) => (
                  <React.Fragment key={p.tactic}>
                    {i > 0 && <span className="corr-arrow">→</span>}
                    <div className={`corr-phase sev-${p.max_severity}`} title={p.techniques.join(", ")}>
                      <b>{p.tactic}</b>
                      <small>{p.domains.map((d) => DOMAIN_ICON[d]).join(" ")} · {p.evidence_refs.length}</small>
                    </div>
                  </React.Fragment>
                ))}
                {env.attack_chain.phases.length === 0 && <span className="corr-hint">No tactic-mapped findings.</span>}
              </div>
              <p className="log-raw" style={{ marginTop: 12 }}>{env.attack_chain.narrative}</p>
            </div>

            <h2 className="section-title">Correlations <span className="section-count">{env.correlations.length}</span></h2>
            {env.correlations.length === 0 && <p className="result-empty">No cross-domain correlations. Check the limitations below before reading this as “clean”.</p>}
            {env.correlations.map((c, i) => (
              <div key={c.correlation_id} className={`forensic-card log-finding log-${c.severity}`} style={{ animationDelay: `${i * 0.04}s` }}>
                <div className="log-finding-header">
                  <strong>{c.correlation_id} · {c.title}</strong>
                  <span className={`severity-chip ${c.severity}`}>{c.severity.toUpperCase()}</span>
                </div>
                <div className="log-detail-grid">
                  <span><b>Rule</b>{c.rule_id}</span>
                  <span><b>Domains</b>{c.domains.map((d) => `${DOMAIN_ICON[d]} ${d}`).join(" ↔ ")}</span>
                  <span><b>Confidence</b>{pct(c.confidence)}</span>
                  <span><b>Admissible</b>{admissibleLabel(c.admissible)}</span>
                </div>
                {c.linking_entities.length > 0 && (
                  <div className="corr-entities">
                    {c.linking_entities.map((e) => (
                      <span key={`${e.type}:${e.value}`} className={`corr-entity ${e.strength}`}>{e.type}: <code>{e.value}</code></span>
                    ))}
                  </div>
                )}
                <p className="log-raw"><strong>Observed:</strong> {c.observation_statement}</p>
                <p className="log-explanation"><strong>Interpretation:</strong> {c.interpretation}</p>
                <div className="mem-alternatives">
                  <strong>Benign explanations to rule out</strong>
                  <ul>{c.alternative_explanations.map((alt, j) => <li key={j}>{alt}</li>)}</ul>
                </div>
                <p className="log-raw"><strong>Next step:</strong> {c.analyst_action}</p>
                <p className="log-raw"><strong>Confidence basis:</strong> {c.confidence_basis}</p>
                {c.mitre_attack.length > 0 && (
                  <div className="log-coverage-list mem-mitre">{c.mitre_attack.map((t) => <span key={t}>{t}</span>)}</div>
                )}
                <button
                  className="btn btn-ghost btn-sm corr-evidence-toggle"
                  onClick={() => setOpenEvidence({ ...openEvidence, [c.correlation_id]: !openEvidence[c.correlation_id] })}
                >
                  {openEvidence[c.correlation_id] ? "Hide" : "Show"} cited evidence ({c.evidence_refs.length})
                </button>
                {openEvidence[c.correlation_id] && (
                  <ul className="corr-evidence">
                    {c.evidence_refs.map((ref) => {
                      const item = itemsByRef[ref];
                      return (
                        <li key={ref}>
                          <code>{ref}</code> {DOMAIN_ICON[item?.domain]} <b>{item?.type}</b>
                          {item?.timestamp_utc && <small> · {item.timestamp_utc}</small>}
                          <div>{item?.observation}</div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            ))}

            <h2 className="section-title">Cross-domain entities</h2>
            <div className="summary-box flush">
              <div className="table-wrap">
              <table className="history-table">
                <thead><tr><th>Entity</th><th>Type</th><th>Strength</th><th>Domains</th><th>Findings</th></tr></thead>
                <tbody>
                  {env.entity_links.map((l) => (
                    <tr key={l.key}>
                      <td className="cell-mono" style={{ overflowWrap: "anywhere" }}>{l.value}</td>
                      <td>{l.type}{l.scope ? ` (${l.scope})` : ""}</td>
                      <td><span className={`corr-entity ${l.strength}`}>{l.strength}</span></td>
                      <td>{l.domains.map((d) => DOMAIN_ICON[d]).join(" ")}</td>
                      <td className="cell-mono">{l.evidence_refs.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
              {env.entity_links.length === 0 && <div style={{ padding: 20, textAlign: "center" }}>No entity appears in more than one domain.</div>}
            </div>

            <h2 className="section-title">Unified timeline</h2>
            <div className="btn-group" style={{ marginBottom: 12 }}>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowContext(!showContext)}>
                {showContext ? "Findings only" : "Include memory context events"}
              </button>
            </div>
            <p className="corr-hint">
              Only real timestamps are placed. Untimed findings, not placed:{" "}
              {Object.entries(env.untimed_findings || {}).map(([d, n]) => `${DOMAIN_ICON[d]} ${n}`).join("  ")}
            </p>
            <div className="timeline">
              {timeline.map((t, i) => (
                <div key={t.event_id} className="timeline-item" style={{ animationDelay: `${Math.min(i, 30) * 0.03}s` }}>
                  {/* UTC, as recorded: local time would misalign sources for anyone reading in another zone */}
                  <div className="timeline-time">{t.timestamp_utc.replace("T", " ").replace("Z", " UTC")} {DOMAIN_ICON[t.source_domain]}</div>
                  <div className="timeline-event">
                    <strong>{t.type}</strong> — {t.description}
                    {t.correlation_refs.length > 0 && <small className="corr-tl-refs"> {t.correlation_refs.join(", ")}</small>}
                  </div>
                </div>
              ))}
              {timeline.length === 0 && <p className="corr-hint">No timestamped findings.</p>}
            </div>

            <h2 className="section-title">Limitations</h2>
            <div className="summary-box">
              <ul className="mem-limitations">{env.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
            </div>
          </>
        )}
      </div>
    </>
  );
};

export default CorrelationPage;
