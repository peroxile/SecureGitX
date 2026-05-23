// Responsibilities:
//   - Create shared resources (DiagnosticCollection, OutputChannel)
//   - Register all commands via command.ts
//   - Optionally trigger a staged scan on file save (opt-in via setting)
//  - Re-register the save listener when the scanOnSave setting changes
//   - Clean up on deactivate

import * as vscode from "vscode";
import * as commands from "./command";
import * as diagnostics from "./diagnostics";
import * as scanner from "./scanner";

let collection: vscode.DiagnosticCollection | undefined;
let output: vscode.OutputChannel | undefined;
let saveListener: vscode.Disposable | undefined;

// Lifecycle

export function activate(context: vscode.ExtensionContext): void {
  collection = vscode.languages.createDiagnosticCollection("securegitx");
  output = vscode.window.createOutputChannel("SecureGitX");

  context.subscriptions.push(collection, output);

  commands.registerAll(context, {
    collection,
    output,
  });

  registerSaveListener(context);

  // Re-register the save listener whenever settings change
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("securegitx.scanOnSave")) {
        saveListener?.dispose();
        saveListener = undefined;
        registerSaveListener(context);
      }
    })
  );

  output.appendLine("SecureGitX activated");
}

export function deactivate(): void {
  saveListener?.dispose();
  saveListener = undefined;
  collection?.clear();
  collection?.dispose();
  output?.dispose();
}

// Save listener
function registerSaveListener(context: vscode.ExtensionContext): void {
  const cfg = vscode.workspace.getConfiguration("securegitx");
  if (!cfg.get<boolean>("scanOnSave", false)) {
    return;
  }

  saveListener = vscode.workspace.onDidSaveTextDocument(async () => {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!root || !collection || !output) return;

    try {
      const execPath = scanner.resolveExecutable(root);
      const result = await scanner.scanStaged(execPath, root);

      output.appendLine(
        `[autoscan] exit=${result.exit_code} findings=${result.findings.length}`
      );

      if (result.error) {
        output.appendLine(`[autoscan] error: ${result.error}`);
        diagnostics.clear(collection);
        return;
      }

      diagnostics.applyFindings(collection, result.findings, root);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      output.appendLine(`[autoscan] exception: ${msg}`);
      diagnostics.clear(collection);
    }
  });

  context.subscriptions.push(saveListener);
}
