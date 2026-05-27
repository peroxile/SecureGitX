// Responsibilities:
//   - Resolve the securegitx executable
//   - Spawn CLI processes and collect human-readable output for scans
//   - Spawn CLI processes and collect text output for non-scan commands
//   - Parse scan output into typed Finding objects

import * as cp from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

// Types — mirror securegitx output schema

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

export interface CommandResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  error?: string;
}

// Executable resolution

export function resolveExecutable(workspaceRoot: string): string {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  const customPath = cfg.get<string>("executablePath", "").trim();

  if (customPath) {
    const resolved = path.isAbsolute(customPath)
      ? customPath
      : path.resolve(workspaceRoot, customPath);

    if (fs.existsSync(resolved)) {
      return resolved;
    }
  }

  const candidates = [
    path.join(workspaceRoot, ".venv", "bin", "securegitx"),
    path.join(workspaceRoot, ".venv", "Scripts", "securegitx.exe"),
    path.join(workspaceRoot, "venv", "bin", "securegitx"),
    path.join(workspaceRoot, "venv", "Scripts", "securegitx.exe"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return "securegitx";
}

// Scan commands

export async function scanStaged(
  execPath: string,
  cwd: string
): Promise<ScanResult> {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  const failOn = cfg.get<string>("failOn", "high");

  return runScanCommand(
    execPath,
    ["scan", "--staged", "--fail-on", failOn],
    cwd
  );
}

export async function scanTracked(
  execPath: string,
  cwd: string
): Promise<ScanResult> {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  const failOn = cfg.get<string>("failOn", "high");

  return runScanCommand(
    execPath,
    ["scan", "--tracked", "--fail-on", failOn],
    cwd
  );
}

// Install / update / uninstall

export async function installHook(
  execPath: string,
  cwd: string
): Promise<string> {
  const result = await runTextCommand(execPath, ["hook", "install"], cwd);
  if (result.error) throw new Error(result.error);
  return result.stdout.trim() || "Hook installed";
}

export async function uninstallHook(
  execPath: string,
  cwd: string
): Promise<string> {
  const result = await runTextCommand(execPath, ["hook", "uninstall"], cwd);
  if (result.error) throw new Error(result.error);
  return result.stdout.trim() || "Hook uninstalled";
}

export async function updateRules(
  execPath: string,
  cwd: string
): Promise<string> {
  const result = await runTextCommand(execPath, ["rules", "update"], cwd);
  if (result.error) throw new Error(result.error);
  return result.stdout.trim() || "Rules updated";
}

// Internal runners

function runScanCommand(
  execPath: string,
  args: string[],
  cwd: string
): Promise<ScanResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let finished = false;

    const proc = cp.spawn(execPath, args, {
      cwd,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      shell: false,
    });

    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      proc.kill();
      resolve({
        findings: [],
        summary: emptySummary(),
        exit_code: -1,
        error: "securegitx timed out while scanning",
      });
    }, 30_000);

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({
        findings: [],
        summary: emptySummary(),
        exit_code: -1,
        error:
          `Could not launch securegitx: ${err.message}. ` +
          `Check the 'securegitx.executablePath' setting.`,
      });
    });

    proc.on("close", (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);

      const combined = `${stdout}\n${stderr}`.trim();
      const parsed = parseScanOutput(combined);

      resolve({
        findings: parsed.findings,
        summary: parsed.summary,
        exit_code: code ?? 0,
        error:
          code !== null && code !== 0 && code !== 1
            ? stderr.trim() || `securegitx exited with code ${code}`
            : parsed.error,
      });
    });
  });
}

function runTextCommand(
  execPath: string,
  args: string[],
  cwd: string
): Promise<CommandResult> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let finished = false;

    const proc = cp.spawn(execPath, args, {
      cwd,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      shell: false,
    });

    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      proc.kill();
      resolve({
        exit_code: -1,
        stdout,
        stderr,
        error: "securegitx timed out",
      });
    }, 30_000);

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({
        exit_code: -1,
        stdout,
        stderr,
        error:
          `Could not launch securegitx: ${err.message}. ` +
          `Check the 'securegitx.executablePath' setting.`,
      });
    });

    proc.on("close", (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);

      resolve({
        exit_code: code ?? 0,
        stdout,
        stderr,
        error:
          code !== null && code !== 0
            ? stderr.trim() || `securegitx exited with code ${code}`
            : undefined,
      });
    });
  });
}

// Text parsing

function parseScanOutput(output: string): ScanResult {
  if (!output.trim()) {
    return {
      findings: [],
      summary: emptySummary(),
      exit_code: 0,
      error: "securegitx returned no output",
    };
  }

  const findings = parseFindingsFromText(output);
  const summary = buildSummary(findings);

  return {
    findings,
    summary,
    exit_code: 0,
    error:
      findings.length === 0 && /commit blocked|finding\(s\)|^✖/im.test(output)
        ? "securegitx reported findings but none could be parsed"
        : undefined,
  };
}

function parseFindingsFromText(output: string): Finding[] {
  const lines = output.split(/\r?\n/);
  const findings: Finding[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();

    const header = parseFindingHeader(line);
    if (!header) {
      i++;
      continue;
    }

    const finding: Finding = {
      rule_id: header.rule_id,
      rule_name: header.rule_name,
      severity: header.severity,
      file: "",
      line_number: 0,
      matched_text: "",
      reason: "",
      remediation: "",
      confidence: "high",
    };

    i++;

    while (i < lines.length) {
      const raw = lines[i].trim();

      if (!raw) {
        i++;
        break;
      }

      if (parseFindingHeader(raw)) {
        break;
      }

      const field = parseField(raw);
      if (field) {
        switch (field.key) {
          case "file": {
            const { file, line_number } = parseFileAndLine(field.value);
            finding.file = file;
            finding.line_number = line_number;
            break;
          }
          case "match":
            finding.matched_text = field.value;
            break;
          case "why":
            finding.reason = field.value;
            break;
          case "fix":
            finding.remediation = field.value;
            break;
        }
      }

      i++;
    }

    if (
      finding.rule_id ||
      finding.file ||
      finding.reason ||
      finding.remediation
    ) {
      findings.push(finding);
    }
  }

  return findings;
}

function parseFindingHeader(
  line: string
): { severity: Severity; rule_name: string; rule_id: string } | undefined {
  // Examples:
  // ✖ [CRITICAL] stripe_api_key (SGX006)
  // ⚠ [HIGH] env_file (SGX103)
  const match = line.match(
    /^[^\[]*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.+?)\s+\(([^)]+)\)\s*$/i
  );

  if (!match) {
    return undefined;
  }

  return {
    severity: match[1].toLowerCase() as Severity,
    rule_name: match[2].trim(),
    rule_id: match[3].trim(),
  };
}

function parseField(
  line: string
): { key: "file" | "match" | "why" | "fix"; value: string } | undefined {
  const match = line.match(/^(File|Match|Why|Fix)\s*:?\s*(.*)$/i);
  if (!match) {
    return undefined;
  }

  const key = match[1].toLowerCase() as "file" | "match" | "why" | "fix";
  const value = match[2].trim();
  return { key, value };
}

function parseFileAndLine(value: string): {
  file: string;
  line_number: number;
} {
  const match = value.match(/^(.*?)(?::(\d+))?$/);
  if (!match) {
    return { file: value.trim(), line_number: 0 };
  }

  const file = match[1].trim();
  const line_number = match[2] ? Number(match[2]) : 0;

  return {
    file,
    line_number: Number.isFinite(line_number) ? line_number : 0,
  };
}

function buildSummary(findings: Finding[]): ScanSummary {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const finding of findings) {
    if (finding.severity in counts) {
      counts[finding.severity] += 1;
    }
  }

  return {
    total: findings.length,
    clean: findings.length === 0,
    by_severity: counts,
  };
}

function emptySummary(): ScanSummary {
  return {
    total: 0,
    clean: true,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
  };
}
