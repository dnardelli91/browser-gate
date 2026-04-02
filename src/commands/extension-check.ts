/**
 * extension-check.ts
 * Analyze browser extension permissions from Chrome Web Store API.
 */

import * as fs from 'fs';
import chalk from 'chalk';

interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  description: string;
  permissions: string[];
  warnings: string[];
  rating: number;
  users: string;
}

const SENSITIVE_PERMISSIONS: Record<string, { severity: 'high' | 'medium' | 'low'; reason: string }> = {
  'tabs': { severity: 'high', reason: 'Can read tab titles, URLs, and metadata — profile tracking' },
  'webRequest': { severity: 'high', reason: 'Can intercept and monitor all HTTP requests — traffic sniffing' },
  'webRequestBlocking': { severity: 'high', reason: 'Can block or modify network requests — MITM capability' },
  'cookies': { severity: 'high', reason: 'Can read/write cookies — session hijacking risk' },
  'storage': { severity: 'medium', reason: 'Can store persistent data locally — tracking/fingerprinting' },
  'history': { severity: 'high', reason: 'Can read browsing history — privacy violation' },
  'topSites': { severity: 'medium', reason: 'Access to most visited sites — behavioral profiling' },
  'bookmarks': { severity: 'high', reason: 'Can read/write bookmarks — data exfiltration' },
  'downloads': { severity: 'high', reason: 'Can manage downloads — malware delivery vector' },
  'downloads.open': { severity: 'high', reason: 'Can open downloads automatically — execution risk' },
  'nativeMessaging': { severity: 'high', reason: 'Can communicate with native applications — privilege escalation' },
  'clipboardRead': { severity: 'high', reason: 'Can read clipboard contents — credential theft' },
  'clipboardWrite': { severity: 'medium', reason: 'Can write to clipboard — injection risk' },
  'proxy': { severity: 'high', reason: 'Can configure proxy settings — traffic redirection' },
  'privacy': { severity: 'high', reason: 'Can override browser privacy settings' },
  'management': { severity: 'high', reason: 'Can manage other extensions — supply-chain risk' },
  'system.cpu': { severity: 'medium', reason: 'Can read CPU info — fingerprinting' },
  'system.memory': { severity: 'medium', reason: 'Can read memory info — fingerprinting' },
  'system.storage': { severity: 'medium', reason: 'Can enumerate storage devices — physical data theft' },
  'desktopCapture': { severity: 'high', reason: 'Can capture desktop — surveillance risk' },
  'pageCapture': { severity: 'high', reason: 'Can capture page content — data exfiltration' },
  'activeTab': { severity: 'medium', reason: 'Temporary access to current tab — targeted attacks' },
  '<all_urls>': { severity: 'high', reason: 'Can access ALL websites — maximum attack surface' },
  '*://*/': { severity: 'high', reason: 'Can access all URLs — equivalent to <all_urls>' },
  'unlimitedStorage': { severity: 'low', reason: 'Can store large amounts of data persistently' },
};

export async function extensionCheck(extensionId: string, options: { output?: string }): Promise<void> {
  console.log(chalk.blue(`\n🔍  BrowserGate — Extension Permission Checker`));
  console.log(chalk.blue(`   Extension ID: ${extensionId}\n`));

  let extensionData: any = null;

  try {
    // Use Chrome Web Store API (public, no auth needed)
    const response = await fetch(
      `https://chrome.google.com/webstore/ajax/detail?reviewType=1&sort=1&id=${encodeURIComponent(extensionId)}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        },
      }
    );

    if (response.ok) {
      const text = await response.text();
      // The response is a JSONP-like format, try to extract meaningful data
      const jsonMatch = text.match(/\{"response":\{"extension":\{.*\}\}\}/);
      if (jsonMatch) {
        try {
          extensionData = JSON.parse(jsonMatch[0]);
        } catch {
          // Fall through to mock data
        }
      }
    }
  } catch {
    // Network error or parse error — use fallback
  }

  // Fallback: try to fetch from manifest.json endpoint
  if (!extensionData) {
    try {
      const manifestUrl = `https://ext.crx.software/chrome/${extensionId}`;
      const resp = await fetch(manifestUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
      if (resp.ok) {
        const data = await resp.json() as any;
        if (data.manifest) {
          extensionData = {
            response: {
              extension: {
                name: data.name || extensionId,
                version: data.manifest.version || 'unknown',
                description: data.manifest.description || '',
                permissions: data.manifest.permissions || [],
              }
            }
          };
        }
      }
    } catch {
      // continue
    }
  }

  const permissions: string[] = extensionData?.response?.extension?.permissions || [];
  const name: string = extensionData?.response?.extension?.name || extensionId;
  const version: string = extensionData?.response?.extension?.version || 'unknown';
  const description: string = extensionData?.response?.extension?.description || 'No description available';

  const warnings: string[] = [];

  for (const perm of permissions) {
    const normalizedPerm = perm.replace(/\*/g, '');
    if (SENSITIVE_PERMISSIONS[normalizedPerm]) {
      const info = SENSITIVE_PERMISSIONS[normalizedPerm];
      warnings.push(`[${info.severity.toUpperCase()}] ${perm}: ${info.reason}`);
    } else if (perm.includes('://') || perm === '<all_urls>') {
      warnings.push(`[HIGH] ${perm}: Can access content on matching sites`);
    }
  }

  const result: ExtensionInfo = {
    id: extensionId,
    name,
    version,
    description,
    permissions,
    warnings,
    rating: 0,
    users: 'unknown',
  };

  console.log(chalk.bold(`📦  ${name} (v${version})`));
  console.log(`    ID: ${extensionId}\n`);
  console.log(chalk.gray(`    ${description}\n`));

  console.log(chalk.bold(`🔐  Permissions (${permissions.length}):`));
  if (permissions.length === 0) {
    console.log(chalk.green(`    └─ No permissions requested`));
  } else {
    for (const perm of permissions) {
      const normalizedPerm = perm.replace(/\*/g, '');
      if (SENSITIVE_PERMISSIONS[normalizedPerm]) {
        const sev = SENSITIVE_PERMISSIONS[normalizedPerm].severity;
        const color = sev === 'high' ? chalk.red : sev === 'medium' ? chalk.yellow : chalk.blue;
        console.log(`    ${color('●')} ${perm}`);
      } else if (perm.includes('://') || perm === '<all_urls>') {
        console.log(`    ${chalk.red('●')} ${perm}`);
      } else {
        console.log(`    ${chalk.green('●')} ${perm}`);
      }
    }
  }

  console.log(chalk.bold(`\n⚠️  Warnings (${warnings.length}):`));
  if (warnings.length === 0) {
    console.log(chalk.green(`    └─ No sensitive permission warnings`));
  } else {
    for (const w of warnings) {
      console.log(`    └─ ${w}`);
    }
  }

  console.log('');

  if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify({ extension: result, timestamp: new Date().toISOString() }, null, 2));
    console.log(chalk.blue(`📄  Report saved to ${options.output}`));
  }

  process.exit(warnings.filter(w => w.includes('[HIGH]')).length > 0 ? 1 : 0);
}
