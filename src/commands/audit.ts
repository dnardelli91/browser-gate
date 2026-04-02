/**
 * audit.ts
 * Check node_modules against known-compromised npm packages.
 */

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';

interface AuditResult {
  package: string;
  version: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  reason: string;
}

// Known compromised packages (curated list — extend as needed)
const KNOWN_COMPROMISED: Record<string, { severity: 'critical' | 'high' | 'medium' | 'low'; reason: string }> = {
  'event-stream-flat': { severity: 'critical', reason: 'Flat event-stream with known malicious code injection (event-stream attack variant)' },
  'flatmap-stream': { severity: 'critical', reason: 'Used in event-stream attack — steals cryptocurrency wallets' },
  'cross-env': { severity: 'medium', reason: 'Known to exfiltrate environment variables in certain versions' },
  'pac-resolver': { severity: 'high', reason: 'Prototype pollution vulnerability CVE-2021-23436' },
  'trim-newlines': { severity: 'medium', reason: 'Command injection in some versions' },
  'node-fetch': { severity: 'medium', reason: 'DNS rebinding vulnerability in older versions' },
  'request': { severity: 'high', reason: 'Deprecated with known security issues; discontinued' },
  'moment': { severity: 'low', reason: 'Past ReDoS vulnerabilities; consider alternatives' },
  'left-pad': { severity: 'low', reason: 'Historical supply-chain attack (2016) — removed from npm' },
  'jsonparser': { severity: 'critical', reason: 'Prototype pollution CVE-2019-20149' },
  'marked': { severity: 'high', reason: 'XSS vulnerabilities in older versions' },
  'minimist': { severity: 'high', reason: 'Prototype pollution CVE-2021-44906' },
  'underscore': { severity: 'medium', reason: 'Various prototype pollution CVEs' },
  ' lodash': { severity: 'high', reason: 'Prototype pollution CVEs CVE-2019-10744, CVE-2020-8203' },
};

export async function audit(options: { path?: string; output?: string }): Promise<void> {
  const nodeModulesPath = path.resolve(options.path || './node_modules');
  console.log(chalk.blue(`\n🔍  BrowserGate Audit`));
  console.log(chalk.blue(`   Scanning: ${nodeModulesPath}\n`));

  const results: AuditResult[] = [];

  if (!fs.existsSync(nodeModulesPath)) {
    console.log(chalk.yellow(`⚠️  node_modules not found at ${nodeModulesPath}`));
    console.log(chalk.yellow(`   Run: npm install first, or specify path with --path`));
    process.exit(1);
  }

  try {
    const packages = fs.readdirSync(nodeModulesPath).filter(name => {
      // Skip scoped packages dirs and .bin
      return !name.startsWith('@') && name !== '.bin';
    });

    // Also check scoped packages
    const scopeDirs = fs.readdirSync(nodeModulesPath).filter(name => name.startsWith('@'));
    for (const scope of scopeDirs) {
      try {
        const scopePath = path.join(nodeModulesPath, scope);
        const scopePkgs = fs.readdirSync(scopePath);
        packages.push(`${scope}/${scopePkgs[0]}`); // just check first level
      } catch {
        // skip
      }
    }

    for (const pkg of packages) {
      const pkgPath = path.join(nodeModulesPath, pkg);
      if (!fs.statSync(pkgPath).isDirectory()) continue;

      const packageJsonPath = path.join(pkgPath, 'package.json');
      if (!fs.existsSync(packageJsonPath)) continue;

      try {
        const pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        const pkgName: string = pkgJson.name || pkg;
        const pkgVersion: string = pkgJson.version || 'unknown';

        for (const [compromised, info] of Object.entries(KNOWN_COMPROMISED)) {
          if (pkgName === compromised || pkgName.endsWith(`/${compromised}`)) {
            results.push({
              package: pkgName,
              version: pkgVersion,
              severity: info.severity,
              reason: info.reason,
            });
          }
        }
      } catch {
        // Skip malformed package.json
      }
    }
  } catch (err) {
    console.error(chalk.red(`❌  Error scanning node_modules: ${err}`));
    process.exit(1);
  }

  // Output results
  if (results.length === 0) {
    console.log(chalk.green(`✅  No known-compromised packages detected.\n`));
  } else {
    console.log(chalk.red(`⚠️  Found ${results.length} suspicious package(s):\n`));
    for (const r of results) {
      const color = r.severity === 'critical' ? chalk.red :
                    r.severity === 'high' ? chalk.magenta :
                    r.severity === 'medium' ? chalk.yellow : chalk.blue;
      console.log(`  ${color('[⚠ ' + r.severity.toUpperCase() + ']')} ${chalk.bold(r.package)}@${r.version}`);
      console.log(`    └─ ${r.reason}\n`);
    }
  }

  if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify({ audit: results, timestamp: new Date().toISOString() }, null, 2));
    console.log(chalk.blue(`📄  Report saved to ${options.output}`));
  }

  process.exit(results.length > 0 ? 1 : 0);
}
