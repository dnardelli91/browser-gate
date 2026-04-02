/**
 * install-script-scan.ts
 * Flag suspicious postinstall/prereinstall scripts in node_modules.
 */

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';

interface SuspiciousScript {
  package: string;
  version: string;
  scriptType: string;
  scriptContent: string;
  risk: 'high' | 'medium' | 'low';
  reason: string;
}

// Patterns that indicate potentially malicious install scripts
const SUSPICIOUS_PATTERNS = [
  { pattern: /curl\s+http/i, risk: 'high' as const, reason: 'Fetches remote content during install' },
  { pattern: /wget\s+http/i, risk: 'high' as const, reason: 'Downloads remote content during install' },
  { pattern: /exec\s*\(/i, risk: 'medium' as const, reason: 'Uses exec() — may run arbitrary code' },
  { pattern: /eval\s*\(/i, risk: 'high' as const, reason: 'Uses eval() — code injection risk' },
  { pattern: /process\.env\.[A-Z_]+\s*!==?\s*undefined/i, risk: 'medium' as const, reason: 'Checks for specific env vars — possible credential scanning' },
  { pattern: /\.password|\.secret|\.token|env\..*password/i, risk: 'high' as const, reason: 'References secrets in script' },
  { pattern: /base64\s+-d/i, risk: 'high' as const, reason: 'Decodes base64-encoded payload — common evasion technique' },
  { pattern: /chmod\s+[0-7]{3,4}/i, risk: 'medium' as const, reason: 'Modifies file permissions' },
  { pattern: /rm\s+-rf\s+\$\{/i, risk: 'high' as const, reason: 'Recursive deletion with variable — dangerous pattern' },
  { pattern: /git\s+clone/i, risk: 'medium' as const, reason: 'Clones repository during install' },
  { pattern: /npm\s+publish/i, risk: 'medium' as const, reason: 'May republish packages during install' },
  { pattern: /child_process|spawn|fork/i, risk: 'low' as const, reason: 'Spawns child processes' },
  { pattern: /https?:\/\/gist|https?:\/\/raw\./i, risk: 'high' as const, reason: 'Fetches code from external URL' },
  { pattern: /||\s*curl|&\&amp;\s*curl/i, risk: 'high' as const, reason: 'Conditional curl — often used in attacks' },
];

const SCRIPT_KEYS = ['scripts', 'node_modules', 'dependencies', 'devDependencies', 'peerDependencies'];

export async function installScriptScan(options: { path?: string; output?: string }): Promise<void> {
  const nodeModulesPath = path.resolve(options.path || './node_modules');
  console.log(chalk.blue(`\n🔍  BrowserGate — Install Script Scanner`));
  console.log(chalk.blue(`   Scanning: ${nodeModulesPath}\n`));

  const results: SuspiciousScript[] = [];

  if (!fs.existsSync(nodeModulesPath)) {
    console.log(chalk.yellow(`⚠️  node_modules not found at ${nodeModulesPath}`));
    process.exit(1);
  }

  const scanPackage = (pkgPath: string, packageName: string): void => {
    const pkgJsonPath = path.join(pkgPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return;

    try {
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      const version: string = pkgJson.version || 'unknown';
      const scripts: Record<string, string> = pkgJson.scripts || {};

      for (const [scriptName, scriptContent] of Object.entries(scripts)) {
        // Focus on install-related scripts
        const installRelated = ['postinstall', 'preinstall', 'install', 'postpublish', 'prepublish', 'prepare', 'prepack'];

        if (!installRelated.some(k => scriptName.toLowerCase().includes(k))) continue;
        if (!scriptContent || typeof scriptContent !== 'string') continue;

        const reasons: string[] = [];
        let maxRisk: 'high' | 'medium' | 'low' = 'low';

        for (const { pattern, risk, reason } of SUSPICIOUS_PATTERNS) {
          if (pattern.test(scriptContent)) {
            reasons.push(reason);
            if (risk === 'high' || (risk === 'medium' && maxRisk !== 'high')) {
              maxRisk = risk;
            }
          }
        }

        if (reasons.length > 0 || scriptContent.trim().length > 200) {
          results.push({
            package: packageName,
            version,
            scriptType: scriptName,
            scriptContent: scriptContent.substring(0, 500),
            risk: maxRisk,
            reason: reasons.length > 0 ? reasons.join('; ') : 'Unusually long script — manual review recommended',
          });
        }
      }
    } catch {
      // Skip malformed package.json
    }
  };

  try {
    const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && !entry.name.startsWith('.')) {
        const pkgPath = path.join(nodeModulesPath, entry.name);
        if (entry.name.startsWith('@')) {
          // Scoped packages
          try {
            const scopeEntries = fs.readdirSync(pkgPath, { withFileTypes: true });
            for (const scopeEntry of scopeEntries) {
              if (scopeEntry.isDirectory()) {
                scanPackage(path.join(pkgPath, scopeEntry.name), `${entry.name}/${scopeEntry.name}`);
              }
            }
          } catch {
            // skip
          }
        } else {
          scanPackage(pkgPath, entry.name);
        }
      }
    }
  } catch (err) {
    console.error(chalk.red(`❌  Error scanning: ${err}`));
    process.exit(1);
  }

  if (results.length === 0) {
    console.log(chalk.green(`✅  No suspicious install scripts detected.\n`));
  } else {
    console.log(chalk.red(`⚠️  Found ${results.length} suspicious install script(s):\n`));
    for (const r of results) {
      const color = r.risk === 'high' ? chalk.red :
                    r.risk === 'medium' ? chalk.yellow : chalk.blue;
      console.log(`  ${color('[⚠ ' + r.risk.toUpperCase() + ']')} ${chalk.bold(r.package)}@${r.version} — ${chalk.cyan(r.scriptType)}`);
      console.log(`    └─ ${r.reason}`);
      console.log(`    └─ Script: ${chalk.gray(r.scriptContent.substring(0, 150))}${r.scriptContent.length > 150 ? '...' : ''}\n`);
    }
  }

  if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify({ installScripts: results, timestamp: new Date().toISOString() }, null, 2));
    console.log(chalk.blue(`📄  Report saved to ${options.output}`));
  }

  process.exit(results.length > 0 ? 1 : 0);
}
