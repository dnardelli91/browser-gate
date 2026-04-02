/**
 * report.ts
 * Generate combined security report (JSON or HTML).
 */

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { audit } from './audit';
import { installScriptScan } from './install-script-scan';

export async function report(options: {
  format?: string;
  output?: string;
  path?: string;
}): Promise<void> {
  const format = options.format || 'json';
  const outputPath = options.output || `browser-gate-report.${format}`;
  const nodeModulesPath = path.resolve(options.path || './node_modules');

  console.log(chalk.blue(`\n📊  BrowserGate — Security Report Generator\n`));

  // Run both scans inline to collect data
  const auditResults: any[] = [];
  const installScriptResults: any[] = [];

  // Replicate audit logic inline for report
  if (fs.existsSync(nodeModulesPath)) {
    const KNOWN_COMPROMISED: Record<string, { severity: string; reason: string }> = {
      'event-stream-flat': { severity: 'critical', reason: 'Malicious injection variant' },
      'flatmap-stream': { severity: 'critical', reason: 'event-stream attack' },
      'cross-env': { severity: 'medium', reason: 'Env exfiltration' },
      'pac-resolver': { severity: 'high', reason: 'Prototype pollution CVE-2021-23436' },
      'request': { severity: 'high', reason: 'Deprecated, discontinued' },
      'marked': { severity: 'high', reason: 'XSS vulnerabilities' },
      'minimist': { severity: 'high', reason: 'Prototype pollution CVE-2021-44906' },
      'lodash': { severity: 'high', reason: 'Prototype pollution CVEs' },
    };

    try {
      const packages = fs.readdirSync(nodeModulesPath).filter(n => !n.startsWith('@') && n !== '.bin');
      const scopeDirs = fs.readdirSync(nodeModulesPath).filter(n => n.startsWith('@'));

      const allPkgs = [...packages];
      for (const scope of scopeDirs) {
        try {
          const scopePkgs = fs.readdirSync(path.join(nodeModulesPath, scope));
          scopePkgs.forEach(p => allPkgs.push(`${scope}/${p}`));
        } catch { /* skip */ }
      }

      for (const pkg of allPkgs) {
        const pkgPath = path.join(nodeModulesPath, pkg);
        if (!fs.statSync(pkgPath).isDirectory()) continue;
        const pkgJsonPath = path.join(pkgPath, 'package.json');
        if (!fs.existsSync(pkgJsonPath)) continue;
        try {
          const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
          const pkgName: string = pkgJson.name || pkg;
          const pkgVersion: string = pkgJson.version || 'unknown';
          for (const [compromised, info] of Object.entries(KNOWN_COMPROMISED)) {
            if (pkgName === compromised || pkgName.endsWith(`/${compromised}`)) {
              auditResults.push({ package: pkgName, version: pkgVersion, ...info });
            }
          }
          const scripts: Record<string, string> = pkgJson.scripts || {};
          const installRelated = ['postinstall', 'preinstall', 'install'];
          for (const [scriptName, scriptContent] of Object.entries(scripts)) {
            if (!installRelated.some(k => scriptName.toLowerCase().includes(k))) continue;
            if (scriptContent && typeof scriptContent === 'string' && scriptContent.length > 200) {
              installScriptResults.push({
                package: pkgName,
                version: pkgVersion,
                script: scriptName,
                length: scriptContent.length,
              });
            }
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }

  const reportData = {
    generated: new Date().toISOString(),
    path: nodeModulesPath,
    summary: {
      compromisedPackages: auditResults.length,
      longInstallScripts: installScriptResults.length,
      status: auditResults.length === 0 && installScriptResults.length === 0 ? 'PASS' : 'FAIL',
    },
    compromisedPackages: auditResults,
    longInstallScripts: installScriptResults,
  };

  if (format === 'html') {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BrowserGate Security Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #fafafa; }
    h1 { color: #1a1a2e; }
    .status { padding: 12px 20px; border-radius: 6px; font-weight: bold; }
    .status.pass { background: #d4edda; color: #155724; }
    .status.fail { background: #f8d7da; color: #721c24; }
    .section { background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .item { padding: 10px; border-left: 3px solid #ccc; margin: 8px 0; }
    .critical { border-color: #dc3545; }
    .high { border-color: #fd7e14; }
    .medium { border-color: #ffc107; }
    .low { border-color: #17a2b8; }
    .meta { color: #666; font-size: 0.9em; }
    code { background: #f1f1f1; padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>🔒 BrowserGate Security Report</h1>
  <p class="meta">Generated: ${reportData.generated} | Path: ${reportData.path}</p>
  <div class="status ${reportData.summary.status === 'PASS' ? 'pass' : 'fail'}">
    Status: ${reportData.summary.status} — ${reportData.summary.compromisedPackages} compromised package(s), ${reportData.summary.longInstallScripts} suspicious install script(s)
  </div>

  <div class="section">
    <h2>⚠️ Compromised Packages</h2>
    ${reportData.compromisedPackages.length === 0 ? '<p>None detected ✅</p>' :
      reportData.compromisedPackages.map(p => `
      <div class="item ${p.severity}">
        <strong>${p.package}</strong> <code>${p.version}</code><br>
        <span>[${p.severity.toUpperCase()}] ${p.reason}</span>
      </div>`).join('')}
  </div>

  <div class="section">
    <h2>📦 Long Install Scripts</h2>
    ${reportData.longInstallScripts.length === 0 ? '<p>None detected ✅</p>' :
      reportData.longInstallScripts.map(s => `
      <div class="item medium">
        <strong>${s.package}</strong> <code>${s.version}</code><br>
        Script: <code>${s.script}</code> (${s.length} chars — review recommended)
      </div>`).join('')}
  </div>

  <footer style="text-align:center; color:#999; margin-top:40px;">
    Generated by <a href="https://github.com/dnardelli91/browser-gate">browser-gate</a>
  </footer>
</body>
</html>`;
    fs.writeFileSync(outputPath, html);
    console.log(chalk.blue(`📄  HTML report saved to ${outputPath}`));
  } else {
    fs.writeFileSync(outputPath, JSON.stringify(reportData, null, 2));
    console.log(chalk.blue(`📄  JSON report saved to ${outputPath}`));
  }

  console.log(chalk.green(`\n✅  Report complete.\n`));
}
