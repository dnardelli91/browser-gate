#!/usr/bin/env node
/**
 * BrowserGate CLI
 * Audit npm dependencies, browser extensions, and install scripts for security issues.
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { audit } from './commands/audit';
import { installScriptScan } from './commands/install-script-scan';
import { extensionCheck } from './commands/extension-check';
import { report } from './commands/report';

const program = new Command();

program
  .name('browser-gate')
  .description('Security audit tool for npm dependencies, browser extensions, and install scripts')
  .version('1.0.0');

program
  .command('audit')
  .description('Check node_modules against known-compromised npm packages')
  .option('-p, --path <path>', 'Path to node_modules (default: ./node_modules)', './node_modules')
  .option('-o, --output <file>', 'Output JSON report to file (optional)')
  .action(audit);

program
  .command('install-script-scan')
  .description('Flag suspicious postinstall/prereinstall scripts in node_modules')
  .option('-p, --path <path>', 'Path to node_modules (default: ./node_modules)', './node_modules')
  .option('-o, --output <file>', 'Output JSON report to file (optional)')
  .action(installScriptScan);

program
  .command('extension-check')
  .description('Analyze browser extension permissions from Chrome Web Store')
  .argument('<extension-id>', 'Chrome Web Store extension ID')
  .option('-o, --output <file>', 'Output JSON report to file (optional)')
  .action(extensionCheck);

program
  .command('report')
  .description('Generate combined security report (JSON or HTML)')
  .option('-f, --format <format>', 'Report format: json or html', 'json')
  .option('-o, --output <file>', 'Output file path', 'browser-gate-report.json')
  .option('-p, --path <path>', 'Path to node_modules (default: ./node_modules)', './node_modules')
  .action(report);

program.parse();
