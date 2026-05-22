// Register vscode commands 
// Each command calls scanner.ts (which calls Python), then updates the DiagnosticCollection
// No scanning or diagnostic lives here — this file is a dispatcher

import * as vscode from "vscode";
import * as scanner from "./scanner";
import * as diagnostics from "./diagnostics";


export interface Deps {
  collection: vscode.DiagnosticCollection;
  output: vscode.OutputChannel;
}

function getWorkspaceRoot(): string | undefined {
  const folder = vscode.workspace.workspaceFolders?.[0];
  return folder?.uri.fsPath;
}

function requireWorkspaceRoot(): string | undefined {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage(
      "SecureGitX: open a workspace folder first."
    );
    return undefined;
  }
  return root;
}

// Registration

export function registerAll(context: vscode.ExtensionContext, deps: Deps): void {
  const { collection, output } = deps;

  context.subscriptions.push(
    vscode.commands.registerCommand("securegitx.scanStaged", async () => {
      const cwd = requireWorkspaceRoot();
      if (!cwd) return;
      const execPath = scanner.resolveExecutable(cwd);
      await runScan("staged", execPath, cwd, collection, output);
    }),

    vscode.commands.registerCommand("securegitx.scanTracked", async () => {
      const cwd = requireWorkspaceRoot();
      if (!cwd) return;
      const execPath = scanner.resolveExecutable(cwd);
      await runScan("tracked", execPath, cwd, collection, output);
    }),

    vscode.commands.registerCommand("securegitx.installHook", async () => {
      const cwd = requireWorkspaceRoot();
      if (!cwd) return;
      const execPath = scanner.resolveExecutable(cwd);

      try {
        const msg = await scanner.installHook(execPath, cwd);
        output.appendLine(`[hook] ${msg}`);
        vscode.window.showInformationMessage(`SecureGitX: ${msg}`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        output.appendLine(`[hook] error: ${msg}`);
        vscode.window.showErrorMessage(`SecureGitX: ${msg}`);
      }
    }),

    vscode.commands.registerCommand("securegitx.updateRules", async () => {
      const cwd = requireWorkspaceRoot();
      if (!cwd) return;
      const execPath = scanner.resolveExecutable(cwd);

      output.show(true);
      output.appendLine("[rules] Checking for updates...");

      try {
        const msg = await scanner.updateRules(execPath, cwd);
        output.appendLine(`[rules] ${msg}`);
        vscode.window.showInformationMessage(`SecureGitX: ${msg}`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        output.appendLine(`[rules] error: ${msg}`);
        vscode.window.showErrorMessage(`SecureGitX: ${msg}`);
      }
    }),

    vscode.commands.registerCommand("securegitx.clearDiagnostics", () => {
      diagnostics.clear(collection);
      output.appendLine("[diagnostics] Cleared");
    })
  );
}

// Shared scan runner

async function runScan(
  mode: "staged" | "tracked",
  execPath: string,
  cwd: string,
  collection: vscode.DiagnosticCollection,
  output: vscode.OutputChannel
): Promise<void> {
  const label = mode === "staged" ? "staged changes" : "all tracked files";

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Window,
      title: `SecureGitX: scanning ${label}…`,
      cancellable: false,
    },
    async () => {
      const result =
        mode === "staged"
          ? await scanner.scanStaged(execPath, cwd)
          : await scanner.scanTracked(execPath, cwd);

      // Log raw exit code for debugging 
      output.appendLine(
        `[scan:${mode}] exit=${result.exit_code} findings=${result.findings.length}`
      );

      if (result.error) {
        output.appendLine(`[scan:${mode}] error: ${result.error}`);
        const choice = await vscode.window.showErrorMessage(
          `SecureGitX error: ${result.error}`,
          "Open Output"
        );
        if (choice === "Open Output") output.show(true);
        return;
      }

      diagnostics.applyFindings(collection, result.findings, cwd);

      const count = result.findings.length;
      if (count === 0) {
        vscode.window.showInformationMessage("SecureGitX: no secrets detected ✓");
        return;
      }

      const bySeverity = result.summary?.by_severity ?? {};
      const detail = [
        bySeverity.critical ? `${bySeverity.critical} critical` : "",
        bySeverity.high ? `${bySeverity.high} high` : "",
        bySeverity.medium ? `${bySeverity.medium} medium` : "",
        bySeverity.low ? `${bySeverity.low} low` : "",
      ]
        .filter(Boolean)
        .join(", ");

      const pick = await vscode.window.showWarningMessage(
        `SecureGitX: ${count} finding(s)${detail ? ` — ${detail}` : ""}`,
        "Open Problems"
      );

      if (pick === "Open Problems") {
        await vscode.commands.executeCommand("workbench.action.problems.focus");
      }
    }
  );
}