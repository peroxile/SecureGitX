// Responsibilities:
//   - Resolve the securegitx executable
//   - Spawn CLI processes and collect JSON output
//   - Parse output into typed Finding objects

import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

// Types — mirror securegitx JSON output schema

export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  file: string;
  line_number: number;
  matched_text: string;
  reason: string;
  remediation: string;
  confidence: Confidence;
}

export interface ScanSummary {
  total: number;
  clean: boolean;
  by_severity: Record<Severity, number>;
}

export interface ScanResult {
  findings: Finding[];
  summary: ScanSummary;
  exit_code: number;
  error?: string;
}

// Executable resolution

// Find the securegitx executable in priority order:
//  1. securegitx.executablePath setting
//   2. .venv/bin/securegitx  (POSIX) or .venv\Scripts\securegitx.exe  (Windows)
//   3. securegitx in PATH

export function resolveExecutable(workspaceRoot: string): string {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  const customPath = cfg.get<string>("executablePath", "").trim();

  if (customPath && fs.existsSync(customPath)) {
    return customPath;
  }

  // Virtual-environment paths (POSIX then Windows)
  const candidates = [
    path.join(workspaceRoot, ".venv", "bin", "securegitx"),
    path.join(workspaceRoot, ".venv", "Scripts", "securegitx.exe"),
    path.join(workspaceRoot, "venv", "bin", "securegitx"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }

  return "securegitx"; // fall back to PATH
}

// Scan commands
// Scan staged changes — primary mode, mirrors what the pre-commit hook does.
export async function scanStaged(
  execPath: string,
  cwd: string
): Promise<ScanResult> {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  const failOn = cfg.get<string>("failOn", "high");
  return _run(
    execPath,
    ["scan", "--staged", "--format", "json", "--quiet", "--fail-on", failOn],
    cwd
  );
}

// Scan all tracked files — explicit user request only.
export async function scanTracked(
  execPath: string,
  cwd: string
): Promise<ScanResult> {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  const failOn = cfg.get<string>("failOn", "high");
  return _run(
    execPath,
    ["scan", "--tracked", "--format", "json", "--quiet", "--fail-on", failOn],
    cwd
  );
}

// Install the pre-commit hook in the current repo.
export async function installHook(
  execPath: string,
  cwd: string
): Promise<string> {
  const result = await _run(execPath, ["hook", "install"], cwd);
  return result.error ?? "Hook installed";
}

//  Update the rule bundle (requires updater.py to be wired in).
export async function updateRules(
  execPath: string,
  cwd: string
): Promise<string> {
  const result = await _run(execPath, ["rules", "update"], cwd);
  return result.error ?? "Rules updated";
}

// Internal process runner

function _run(
  execPath: string,
  args: string[],
  cwd: string
): Promise<ScanResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";

    const proc = cp.spawn(execPath, args, {
      cwd,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
    });

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err) => {
      // Executable not found or couldn't be spawned
      resolve({
        findings: [],
        summary: _emptySummary(),
        exit_code: -1,
        error:
          `Could not launch securegitx: ${err.message}. ` +
          `Check the 'securegitx.executablePath' setting.`,
      });
    });

    proc.on("close", (code) => {
      // exit 0 = clean, exit 1 = findings above threshold, anything else = error
      const isError = code !== null && code !== 0 && code !== 1;
      resolve({
        findings: _parseFindings(stdout),
        summary: _parseSummary(stdout),
        exit_code: code ?? 0,
        error: isError
          ? stderr.trim() || `securegitx exited with code ${code}`
          : undefined,
      });
    });
  });
}

// Output parsers

function _parseFindings(output: string): Finding[] {
  if (!output.trim()) return [];
  try {
    const data = JSON.parse(output);
    // Support both bare array and {findings: [...]} object
    return Array.isArray(data) ? data : data.findings ?? [];
  } catch {
    return [];
  }
}

function _parseSummary(output: string): ScanSummary {
  if (!output.trim()) return _emptySummary();
  try {
    const data = JSON.parse(output);
    if (data.summary) return data.summary as ScanSummary;
  } catch {
    // ignore
  }
  return _emptySummary();
}

function _emptySummary(): ScanSummary {
  return {
    total: 0,
    clean: true,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
  };
}
