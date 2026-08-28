/**
 * diskAgent.js
 * ─────────────────────────────────────────────────────────────
 * Forensic disk analysis agent using Sleuth Kit (fls + fsstat).
 *
 * Input  : path to a raw disk image (.img / .dd / .raw / .ad1)
 * Output : { findings[], meta{} }  — compatible with correlationAgent
 * ─────────────────────────────────────────────────────────────
 */

import { exec } from "child_process";
import path from "path";
import fs from "fs";

// ─── Sleuth Kit binary path ────────────────────────────────────
// Override with SLEUTHKIT_BIN env variable if installed elsewhere
const SLEUTHKIT_BIN =
  process.env.SLEUTHKIT_BIN ||
  "C:\\Users\\Ashmitha U\\Downloads\\sleuthkit-4.14.0-win32\\sleuthkit-4.14.0-win32\\bin";

const FLS_PATH    = path.join(SLEUTHKIT_BIN, "fls.exe");
const FSSTAT_PATH = path.join(SLEUTHKIT_BIN, "fsstat.exe");
const MMLS_PATH   = path.join(SLEUTHKIT_BIN, "mmls.exe");

// ─── Severity scoring weights ──────────────────────────────────
const SEVERITY_SCORE = { info: 1, low: 3, medium: 8, high: 20, critical: 35 };

// ─── Suspicious file extensions ───────────────────────────────
const SUSPICIOUS_EXTENSIONS = new Set([
  ".exe", ".dll", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
  ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
  ".scr", ".com", ".hta", ".msi", ".msp",
]);

// Files that match these names are always flagged critical
const SUSPICIOUS_NAMES = [
  /^nc\.exe$/i,
  /^ncat\.exe$/i,
  /^mimikatz/i,
  /^pwdump/i,
  /^fgdump/i,
  /^procdump/i,
  /^psexec/i,
  /^wce\.exe$/i,
  /^meterpreter/i,
  /^cobalt/i,
  /^beacon\.exe$/i,
  /^payload\.exe$/i,
  /^shell\.exe$/i,
  /^rat\.exe$/i,
  /^keylog/i,
  /^cryptominer/i,
  /\.tmp\.exe$/i,
  /\d{6,}\.exe$/i,
];

// Executables INSIDE these paths are considered normal system files.
// Uses both forward and back slash to handle fls output on Windows.
const SYSTEM_PATH_PATTERNS = [
  /[/\\]Windows[/\\]/i,
  /[/\\]Program Files[/\\]/i,
  /[/\\]Program Files \(x86\)[/\\]/i,
  /[/\\]ProgramData[/\\]Microsoft[/\\]/i,
  /[/\\]System32[/\\]/i,
  /[/\\]SysWOW64[/\\]/i,
  /[/\\]WinSxS[/\\]/i,
];

// ─── Helpers ──────────────────────────────────────────────────

/**
 * Run a shell command. Always resolves — never rejects.
 * A failed tool must not abort the whole agent.
 */
function runCommand(command) {
  return new Promise((resolve) => {
    exec(command, { maxBuffer: 100 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({ stdout: stdout || "", stderr: stderr || "", error });
    });
  });
}

/**
 * Use mmls to find the first partition offset (in sectors).
 * Returns 0 if the image has no partition table or mmls fails.
 */
async function detectPartitionOffset(imagePath) {
  const { stdout } = await runCommand(`"${MMLS_PATH}" "${imagePath}"`);
  if (!stdout) return 0;

  // mmls output rows look like:
  //   000:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
  //   001:  -----   0000000000   0000000062   0000000063   Unallocated
  //   002:  DOS FAT (32 Bit) (0x0b)  ...
  // We want the Start sector of the first actual data partition.
  const lines = stdout.split("\n");
  for (const line of lines) {
    // Skip metadata / unallocated rows
    if (/Meta|Unallocated|-----/i.test(line)) continue;
    // Match a numeric start sector (third column)
    const match = line.match(/^\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      return parseInt(match[1], 10); // start sector of first partition
    }
  }
  return 0;
}

/**
 * Filesystem types to try when auto-detection fails.
 * Ordered by frequency in forensic images.
 */
const FS_TYPES = ["fat16", "fat32", "ntfs", "ext2", "ext3", "ext4", "fat"];

/**
 * Run fls with automatic filesystem-type fallback.
 *
 * Strategy:
 *   1. Try fls without -f (let Sleuth Kit auto-detect) — works for
 *      partitioned images and most NTFS volumes.
 *   2. If stdout is empty, retry with each type in FS_TYPES until
 *      one produces output — handles raw FAT16/FAT32 volumes that
 *      have no MBR/GPT and cannot be auto-detected.
 *
 * Returns { stdout, fsType } where fsType is "auto" or the -f value used.
 */
async function runFlsWithFallback(imagePath, offsetFlag) {
  // Attempt 1 — auto-detect (works for partitioned + most NTFS)
  const autoCmd = `"${FLS_PATH}" -r -p ${offsetFlag} "${imagePath}"`.trim();
  console.log(`[DiskAgent] fls (auto): ${autoCmd}`);
  const auto = await runCommand(autoCmd);

  if (auto.stdout && auto.stdout.trim().length > 0) {
    return { stdout: auto.stdout, fsType: "auto" };
  }

  console.log(`[DiskAgent] fls auto-detect returned no output — trying explicit filesystem types`);

  // Attempt 2 — try each filesystem type explicitly
  for (const fsType of FS_TYPES) {
    const cmd = `"${FLS_PATH}" -f ${fsType} -r -p ${offsetFlag} "${imagePath}"`.trim();
    console.log(`[DiskAgent] fls -f ${fsType}: ${cmd}`);
    const result = await runCommand(cmd);
    if (result.stdout && result.stdout.trim().length > 0) {
      console.log(`[DiskAgent] fls succeeded with -f ${fsType}`);
      return { stdout: result.stdout, fsType };
    }
  }

  // Nothing worked — return empty
  console.warn(`[DiskAgent] fls produced no output with any filesystem type`);
  return { stdout: "", fsType: "unknown" };
}

/**
 * Run fsstat with automatic filesystem-type fallback.
 * Same strategy as runFlsWithFallback.
 */
async function runFsstatWithFallback(imagePath, offsetFlag) {
  const autoCmd = `"${FSSTAT_PATH}" ${offsetFlag} "${imagePath}"`.trim();
  const auto = await runCommand(autoCmd);
  if (auto.stdout && auto.stdout.trim().length > 0) {
    return auto.stdout;
  }

  for (const fsType of FS_TYPES) {
    const cmd = `"${FSSTAT_PATH}" -f ${fsType} ${offsetFlag} "${imagePath}"`.trim();
    const result = await runCommand(cmd);
    if (result.stdout && result.stdout.trim().length > 0) {
      return result.stdout;
    }
  }

  return "";
}

/**
 * Parse one line of `fls -r -p` output into a structured entry.
 *
 * fls recursive + full-path format:
 *   r/r 5:      Windows/System32/notepad.exe
 *   d/d * 12:   Users/admin/Desktop
 *   r/r * 99:   $OrphanFiles/deleted.exe
 *
 * Returns null for blank or unparseable lines.
 */
function parseFlsLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;

  // Deletion marker is an asterisk anywhere before the filename
  const isDeleted = /\*/.test(trimmed);

  // Split on tab — fls separates type+inode from path with a tab
  const tabIdx = trimmed.indexOf("\t");
  let filePath = "";

  if (tabIdx !== -1) {
    filePath = trimmed.slice(tabIdx + 1).trim();
  } else {
    // Fallback: strip the "r/r 1234: " or "d/d * 1234: " prefix
    filePath = trimmed.replace(/^[drlu-]\/[drlu-]\s+\*?\s*\d+[-:]?\d*:\s*/, "").trim();
  }

  if (!filePath || filePath.startsWith("$")) return null; // skip metadata entries

  // Normalise separators — fls on Windows can output either
  const normPath = filePath.replace(/\\/g, "/");
  const fileName = normPath.split("/").pop();
  if (!fileName) return null;

  const ext    = path.extname(fileName).toLowerCase();
  const isDir  = trimmed.startsWith("d/");

  return { rawLine: trimmed, filePath: normPath, fileName, ext, isDir, isDeleted };
}

/**
 * Classify a parsed entry into a finding, or return null if benign.
 */
function classifyEntry(entry) {
  const { filePath, fileName, ext, isDeleted, isDir } = entry;
  if (isDir) return null;

  const isSuspiciousExt  = SUSPICIOUS_EXTENSIONS.has(ext);
  const isSuspiciousName = SUSPICIOUS_NAMES.some((re) => re.test(fileName));
  const isSystemPath     = SYSTEM_PATH_PATTERNS.some((re) => re.test(filePath));

  // ── Deleted file ──────────────────────────────────────────
  if (isDeleted) {
    const sev = isSuspiciousExt || isSuspiciousName ? "high" : "medium";
    return {
      type:        "Deleted File",
      category:    "File System Artifact",
      severity:    sev,
      explanation: isSuspiciousExt || isSuspiciousName
        ? `Deleted executable/script "${fileName}" found — attacker may have removed evidence.`
        : `Deleted file "${fileName}" found. Recovery may reveal additional evidence.`,
      filePath,
      fileName,
      ext,
      deleted:    true,
      suspicious: isSuspiciousExt || isSuspiciousName,
      timestamp:  null,
    };
  }

  // ── Known attacker tool ───────────────────────────────────
  if (isSuspiciousName) {
    return {
      type:        "Known Attacker Tool",
      category:    "Malicious Executable",
      severity:    "critical",
      explanation: `"${fileName}" matches a known attacker tool pattern. Immediate investigation required.`,
      filePath,
      fileName,
      ext,
      deleted:    false,
      suspicious: true,
      timestamp:  null,
    };
  }

  // ── Executable outside standard system directories ────────
  if (isSuspiciousExt && !isSystemPath) {
    return {
      type:        "Suspicious Executable",
      category:    "Suspicious File",
      severity:    "high",
      explanation: `Executable/script "${fileName}" found outside standard system directories. May be malware or a dropped payload.`,
      filePath,
      fileName,
      ext,
      deleted:    false,
      suspicious: true,
      timestamp:  null,
    };
  }

  return null; // benign
}

/**
 * Parse fsstat output into a plain metadata object.
 */
function parseFsstat(output) {
  if (!output) return {};
  const meta = {};
  const pick = (key, pattern) => {
    const m = output.match(pattern);
    if (m?.[1]) meta[key] = m[1].trim();
  };
  pick("fileSystemType", /File System Type:\s*(.+)/i);
  pick("volumeName",     /Volume Name:\s*(.+)/i);
  pick("volumeID",       /Volume ID:\s*(.+)/i);
  pick("totalSectors",   /Total Sector Count:\s*(\d+)/i);
  pick("sectorSize",     /Sector Size:\s*(\d+)/i);
  pick("clusterSize",    /Cluster Size:\s*(\d+)/i);
  pick("lastMountTime",  /Last Mount Time:\s*(.+)/i);
  pick("lastWriteTime",  /Last Written Time:\s*(.+)/i);
  return meta;
}

// ─── Main export ──────────────────────────────────────────────

/**
 * analyzeDisk(filePath)
 *
 * @param {string} filePath  Path to disk image (.img / .dd / .raw / .ad1)
 * @returns {Promise<{ findings: object[], meta: object }>}
 */
const analyzeDisk = async (filePath) => {
  const fullPath = path.resolve(filePath);

  if (!fs.existsSync(fullPath)) {
    throw new Error(`Disk image not found: ${fullPath}`);
  }

  const stat = fs.statSync(fullPath);
  if (stat.size === 0) {
    throw new Error("Disk image file is empty.");
  }

  console.log(`[DiskAgent] Image: ${fullPath} (${(stat.size / 1024 / 1024).toFixed(1)} MB)`);

  // ── Step 1: Detect partition offset so fls reads the right filesystem ──
  let partitionOffset = 0;
  try {
    partitionOffset = await detectPartitionOffset(fullPath);
    console.log(`[DiskAgent] Partition offset: ${partitionOffset} sectors`);
  } catch (_) {
    // mmls not available or plain image with no partition table — use 0
  }

  const offsetFlag = partitionOffset > 0 ? `-o ${partitionOffset}` : "";

  // ── Step 2: Run fls — recursive, full paths, with fs-type fallback ──
  const { stdout: flsOut, fsType: detectedFsType } = await runFlsWithFallback(fullPath, offsetFlag);

  if (!flsOut) {
    console.warn(`[DiskAgent] fls produced no output — image may be unsupported or corrupt`);
  }

  // ── Step 3: Run fsstat — volume metadata, with fs-type fallback ──
  const fsstatOut = await runFsstatWithFallback(fullPath, offsetFlag);
  const volumeMeta = parseFsstat(fsstatOut);

  // Surface the detected filesystem type if fsstat didn't find it
  if (!volumeMeta.fileSystemType && detectedFsType !== "auto" && detectedFsType !== "unknown") {
    volumeMeta.fileSystemType = detectedFsType.toUpperCase();
  }

  // ── Step 4: Parse every fls line ──────────────────────────
  const lines    = flsOut.split("\n");
  const findings = [];
  const stats    = {
    totalEntries:    0,
    deletedFiles:    0,
    deletedDirs:     0,
    suspiciousFiles: 0,
    executableFiles: 0,
    directories:     0,
  };

  for (const line of lines) {
    const entry = parseFlsLine(line);
    if (!entry) continue;

    stats.totalEntries++;
    if (entry.isDir)                         stats.directories++;
    if (entry.isDeleted &&  entry.isDir)     stats.deletedDirs++;
    if (entry.isDeleted && !entry.isDir)     stats.deletedFiles++;
    if (!entry.isDir && SUSPICIOUS_EXTENSIONS.has(entry.ext)) stats.executableFiles++;

    const finding = classifyEntry(entry);
    if (finding) {
      stats.suspiciousFiles++;
      findings.push(finding);
    }
  }

  // ── Step 5: Risk score ────────────────────────────────────
  const riskScore = Math.min(
    100,
    findings.reduce((sum, f) => sum + (SEVERITY_SCORE[f.severity] || 0), 0),
  );
  const risk = riskScore >= 65 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";

  // ── Step 6: Aggregate breakdown ──────────────────────────
  const bySeverity = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const byCategory = findings.reduce((acc, f) => {
    acc[f.category] = (acc[f.category] || 0) + 1;
    return acc;
  }, {});

  const summary = findings.length === 0
    ? `No suspicious artifacts detected. ${stats.totalEntries} entries scanned.`
    : `${findings.length} finding(s) in ${stats.totalEntries} entries. ` +
      `${stats.deletedFiles} deleted file(s). Risk: ${risk} (${riskScore}/100).`;

  console.log(`[DiskAgent] Complete — ${findings.length} findings, risk ${risk}`);

  return {
    findings,
    meta: {
      totalEntries:    stats.totalEntries,
      deletedFiles:    stats.deletedFiles,
      deletedDirs:     stats.deletedDirs,
      suspiciousFiles: stats.suspiciousFiles,
      executableFiles: stats.executableFiles,
      directories:     stats.directories,
      risk,
      riskScore,
      bySeverity,
      byCategory,
      volumeInfo:      volumeMeta,
      summary,
      tool:            "Sleuth Kit (fls + fsstat)",
      imagePath:       fullPath,
      imageSizeBytes:  stat.size,
      partitionOffset,
      detectedFsType,
    },
  };
};

export default analyzeDisk;
