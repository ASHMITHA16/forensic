import axios from "axios";

const API = "http://localhost:5000/api";
const POLL_MS = 3000;
const MAX_POLL_FAILURES = 5;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run the memory agent as a background job and resolve with the same body
 * the synchronous endpoint returns ({ analysisId, data, meta }).
 * Real dumps take minutes to hours, longer than a single HTTP request may live.
 */
export async function runMemoryJob(filePath, onProgress) {
  const { data: started } = await axios.post(`${API}/analyze/memory`, { filePath, async: true });

  let failures = 0;
  for (;;) {
    await wait(POLL_MS);

    let job;
    try {
      ({ data: job } = await axios.get(`${API}/analyze/memory/jobs/${started.jobId}`));
      failures = 0;
    } catch (err) {
      // A 404 means the server lost the job (restart); anything else may be a blip
      if (err.response?.status === 404 || ++failures >= MAX_POLL_FAILURES) throw err;
      continue;
    }

    if (job.status === "done") return job.result;
    if (job.status === "failed") {
      const err = new Error(job.error?.message || "Memory analysis failed");
      err.response = { status: job.error?.status, data: { error: job.error?.message, code: job.error?.code } };
      throw err;
    }
    onProgress?.(job);
  }
}

export function describeMemoryProgress(job) {
  if (!job) return "Starting memory agent…";
  const p = job.progress;
  const elapsed = `${Math.floor(job.elapsedS / 60)}m ${job.elapsedS % 60}s`;
  if (!p) return `Verifying evidence hash… (${elapsed})`;
  const runningPlugins = p.stage === "Running Volatility plugins";
  const plugins = runningPlugins && p.pluginsTotal
    ? ` — plugin ${Math.min(p.pluginsDone + 1, p.pluginsTotal)}/${p.pluginsTotal}` : "";
  const current = runningPlugins && p.currentPlugin ? ` (${p.currentPlugin})` : "";
  return `${p.stage}${plugins}${current} · ${elapsed}`;
}
