#!/usr/bin/env node

/**
 * OpenApp CLI - A secure CLI tool to quickly open websites in your browser
 *
 * Security features:
 * - URL validation using URL constructor (prevents malformed URLs)
 * - Protocol whitelist (only http/https allowed)
 * - Shortcut name sanitization (alphanumeric, hyphens, underscores only)
 * - No shell interpolation (uses 'open' package which handles escaping)
 * - Safe JSON file operations with proper error handling
 */

import { Command } from 'commander';
import open from 'open';
import { homedir } from 'os';
import { join } from 'path';
import { readFileSync, writeFileSync, existsSync } from 'fs';

const CONFIG_FILE = join(homedir(), '.openapprc.json');
const VERSION = '1.0.0';

// Built-in shortcuts for popular websites
const BUILT_IN_SHORTCUTS = {
  // Social Media
  youtube: 'https://www.youtube.com',
  facebook: 'https://www.facebook.com',
  twitter: 'https://www.twitter.com',
  x: 'https://www.x.com',
  instagram: 'https://www.instagram.com',
  linkedin: 'https://www.linkedin.com',
  reddit: 'https://www.reddit.com',
  pinterest: 'https://www.pinterest.com',
  tiktok: 'https://www.tiktok.com',
  snapchat: 'https://www.snapchat.com',

  // Productivity & Work
  gmail: 'https://mail.google.com',
  outlook: 'https://outlook.live.com',
  drive: 'https://drive.google.com',
  docs: 'https://docs.google.com',
  sheets: 'https://sheets.google.com',
  slides: 'https://slides.google.com',
  calendar: 'https://calendar.google.com',
  notion: 'https://www.notion.so',
  trello: 'https://trello.com',
  slack: 'https://slack.com',
  discord: 'https://discord.com',
  zoom: 'https://zoom.us',
  meet: 'https://meet.google.com',
  teams: 'https://teams.microsoft.com',

  // Development
  github: 'https://github.com',
  gitlab: 'https://gitlab.com',
  bitbucket: 'https://bitbucket.org',
  stackoverflow: 'https://stackoverflow.com',
  npm: 'https://www.npmjs.com',
  codepen: 'https://codepen.io',
  codesandbox: 'https://codesandbox.io',
  vercel: 'https://vercel.com',
  netlify: 'https://www.netlify.com',

  // Entertainment & Media
  netflix: 'https://www.netflix.com',
  prime: 'https://www.primevideo.com',
  hotstar: 'https://www.hotstar.com',
  spotify: 'https://open.spotify.com',
  twitch: 'https://www.twitch.tv',

  // Shopping
  amazon: 'https://www.amazon.com',
  flipkart: 'https://www.flipkart.com',
  ebay: 'https://www.ebay.com',

  // Search & Information
  google: 'https://www.google.com',
  bing: 'https://www.bing.com',
  duckduckgo: 'https://duckduckgo.com',
  wikipedia: 'https://www.wikipedia.org',

  // AI & Tools
  chatgpt: 'https://chat.openai.com',
  claude: 'https://claude.ai',
  gemini: 'https://gemini.google.com',
  perplexity: 'https://www.perplexity.ai',

  // News
  hackernews: 'https://news.ycombinator.com',
  medium: 'https://medium.com',
  devto: 'https://dev.to'
};

// Supported browsers with their app identifiers
const BROWSERS = {
  chrome: 'chrome',
  firefox: 'firefox',
  safari: 'safari',
  edge: 'msedge',
  brave: 'brave',
  opera: 'opera',
  default: undefined // System default browser
};

/**
 * Validates a URL for security
 * - Must be a valid URL format
 * - Must use http or https protocol only
 * @param {string} urlString - The URL to validate
 * @returns {string} - The validated URL
 * @throws {Error} - If URL is invalid or uses disallowed protocol
 */
function validateUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    throw new Error('URL must be a non-empty string');
  }

  // Trim whitespace
  const trimmedUrl = urlString.trim();

  // Check for dangerous patterns before parsing
  const dangerousPatterns = [
    /javascript:/i,
    /data:/i,
    /vbscript:/i,
    /file:/i,
    /about:/i,
    /blob:/i
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(trimmedUrl)) {
      throw new Error('URL contains disallowed protocol');
    }
  }

  let url;
  try {
    url = new URL(trimmedUrl);
  } catch {
    throw new Error('Invalid URL format. Please provide a valid URL (e.g., https://example.com)');
  }

  // Only allow http and https protocols
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http and https URLs are allowed for security reasons');
  }

  return url.href;
}

/**
 * Validates a shortcut name for security
 * - Only allows alphanumeric characters, hyphens, and underscores
 * - Must be between 1 and 50 characters
 * @param {string} name - The shortcut name to validate
 * @returns {string} - The validated and normalized name (lowercase)
 * @throws {Error} - If name is invalid
 */
function validateShortcutName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('Shortcut name must be a non-empty string');
  }

  const trimmedName = name.trim().toLowerCase();

  if (trimmedName.length === 0 || trimmedName.length > 50) {
    throw new Error('Shortcut name must be between 1 and 50 characters');
  }

  // Only allow alphanumeric, hyphens, and underscores
  const validNamePattern = /^[a-z0-9_-]+$/;
  if (!validNamePattern.test(trimmedName)) {
    throw new Error('Shortcut name can only contain letters, numbers, hyphens, and underscores');
  }

  // Reserved commands that cannot be used as shortcut names
  const reservedNames = ['add', 'remove', 'list', 'search', 'config', 'help', 'version'];
  if (reservedNames.includes(trimmedName)) {
    throw new Error(`"${trimmedName}" is a reserved command and cannot be used as a shortcut name`);
  }

  return trimmedName;
}

/**
 * Validates browser name
 * @param {string} browser - The browser name to validate
 * @returns {string} - The validated browser name
 * @throws {Error} - If browser is not supported
 */
function validateBrowser(browser) {
  if (!browser || typeof browser !== 'string') {
    throw new Error('Browser name must be a non-empty string');
  }

  const normalizedBrowser = browser.trim().toLowerCase();

  if (!Object.prototype.hasOwnProperty.call(BROWSERS, normalizedBrowser)) {
    const supportedBrowsers = Object.keys(BROWSERS).join(', ');
    throw new Error(`Unsupported browser: "${browser}". Supported browsers: ${supportedBrowsers}`);
  }

  return normalizedBrowser;
}

/**
 * Loads configuration from file
 * @returns {Object} - Configuration object with customShortcuts and settings
 */
function loadConfig() {
  const defaultConfig = {
    customShortcuts: {},
    settings: {
      browser: 'default'
    }
  };

  if (!existsSync(CONFIG_FILE)) {
    return defaultConfig;
  }

  try {
    const fileContent = readFileSync(CONFIG_FILE, 'utf-8');
    const config = JSON.parse(fileContent);

    // Validate loaded config structure
    if (typeof config !== 'object' || config === null) {
      console.error('Warning: Invalid config file format. Using defaults.');
      return defaultConfig;
    }

    return {
      customShortcuts: config.customShortcuts || {},
      settings: {
        browser: config.settings?.browser || 'default'
      }
    };
  } catch (error) {
    console.error('Warning: Could not read config file. Using defaults.');
    return defaultConfig;
  }
}

/**
 * Saves configuration to file
 * @param {Object} config - Configuration object to save
 */
function saveConfig(config) {
  try {
    const jsonContent = JSON.stringify(config, null, 2);
    writeFileSync(CONFIG_FILE, jsonContent, 'utf-8');
  } catch (error) {
    throw new Error(`Could not save config: ${error.message}`);
  }
}

/**
 * Gets all shortcuts (built-in + custom)
 * @returns {Object} - Combined shortcuts object
 */
function getAllShortcuts() {
  const config = loadConfig();
  return {
    ...BUILT_IN_SHORTCUTS,
    ...config.customShortcuts
  };
}

/**
 * Opens a URL in the browser
 * @param {string} url - The URL to open
 * @param {Object} options - Options including incognito mode
 */
async function openUrl(url, options = {}) {
  const config = loadConfig();
  const browserName = config.settings.browser;
  const browserApp = BROWSERS[browserName];

  const openOptions = {};

  if (browserApp) {
    openOptions.app = { name: browserApp };

    // Add incognito/private mode arguments
    if (options.incognito) {
      const incognitoArgs = {
        chrome: ['--incognito'],
        firefox: ['--private-window'],
        safari: [], // Safari doesn't support command-line private mode
        msedge: ['--inprivate'],
        brave: ['--incognito'],
        opera: ['--private']
      };

      const args = incognitoArgs[browserApp];
      if (args && args.length > 0) {
        openOptions.app.arguments = args;
      } else if (browserApp === 'safari') {
        console.log('Note: Safari does not support opening in private mode from command line.');
      }
    }
  } else if (options.incognito) {
    console.log('Note: Incognito mode may not work with the system default browser. Set a specific browser using: openapp config browser <browser>');
  }

  try {
    await open(url, openOptions);
  } catch (error) {
    throw new Error(`Could not open URL: ${error.message}`);
  }
}

/**
 * Formats a table for console output
 * @param {Array} rows - Array of [name, url, type] tuples
 */
function printTable(rows) {
  if (rows.length === 0) {
    console.log('No shortcuts found.');
    return;
  }

  // Calculate column widths
  const nameWidth = Math.max(10, ...rows.map(r => r[0].length)) + 2;
  const typeWidth = 10;

  // Print header
  console.log('\n' + '-'.repeat(nameWidth + typeWidth + 60));
  console.log(
    'Name'.padEnd(nameWidth) +
    'Type'.padEnd(typeWidth) +
    'URL'
  );
  console.log('-'.repeat(nameWidth + typeWidth + 60));

  // Print rows
  for (const [name, url, type] of rows) {
    console.log(
      name.padEnd(nameWidth) +
      type.padEnd(typeWidth) +
      url
    );
  }
  console.log('-'.repeat(nameWidth + typeWidth + 60) + '\n');
}

// Initialize Commander
const program = new Command();

program
  .name('openapp')
  .description('A secure CLI tool to quickly open websites in your browser')
  .version(VERSION);

// Command: openapp <shortcut>
program
  .argument('[shortcut]', 'Name of the website shortcut to open')
  .option('-i, --incognito', 'Open in incognito/private mode')
  .action(async (shortcut, options) => {
    if (!shortcut) {
      program.help();
      return;
    }

    try {
      const normalizedName = validateShortcutName(shortcut);
      const shortcuts = getAllShortcuts();

      if (!Object.prototype.hasOwnProperty.call(shortcuts, normalizedName)) {
        console.error(`Error: Shortcut "${shortcut}" not found.`);
        console.log('Use "openapp list" to see available shortcuts.');
        console.log('Use "openapp add <name> <url>" to add a new shortcut.');
        process.exit(1);
      }

      const url = shortcuts[normalizedName];
      console.log(`Opening ${normalizedName}...`);
      await openUrl(url, { incognito: options.incognito });
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Command: openapp add <name> <url>
program
  .command('add <name> <url>')
  .description('Add a custom shortcut')
  .action(async (name, url) => {
    try {
      const validatedName = validateShortcutName(name);
      const validatedUrl = validateUrl(url);

      // Check if it's a built-in shortcut
      if (Object.prototype.hasOwnProperty.call(BUILT_IN_SHORTCUTS, validatedName)) {
        console.error(`Error: "${validatedName}" is a built-in shortcut and cannot be overwritten.`);
        console.log('Please choose a different name for your custom shortcut.');
        process.exit(1);
      }

      const config = loadConfig();
      config.customShortcuts[validatedName] = validatedUrl;
      saveConfig(config);

      console.log(`Successfully added shortcut "${validatedName}" -> ${validatedUrl}`);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Command: openapp remove <name>
program
  .command('remove <name>')
  .description('Remove a custom shortcut')
  .action(async (name) => {
    try {
      const validatedName = validateShortcutName(name);

      // Check if it's a built-in shortcut
      if (Object.prototype.hasOwnProperty.call(BUILT_IN_SHORTCUTS, validatedName)) {
        console.error(`Error: "${validatedName}" is a built-in shortcut and cannot be removed.`);
        process.exit(1);
      }

      const config = loadConfig();

      if (!Object.prototype.hasOwnProperty.call(config.customShortcuts, validatedName)) {
        console.error(`Error: Custom shortcut "${validatedName}" not found.`);
        process.exit(1);
      }

      delete config.customShortcuts[validatedName];
      saveConfig(config);

      console.log(`Successfully removed shortcut "${validatedName}"`);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Command: openapp list
program
  .command('list')
  .description('List all available shortcuts')
  .option('-b, --builtin', 'Show only built-in shortcuts')
  .option('-c, --custom', 'Show only custom shortcuts')
  .action((options) => {
    try {
      const config = loadConfig();
      const rows = [];

      if (!options.custom) {
        for (const [name, url] of Object.entries(BUILT_IN_SHORTCUTS)) {
          rows.push([name, url, 'built-in']);
        }
      }

      if (!options.builtin) {
        for (const [name, url] of Object.entries(config.customShortcuts)) {
          rows.push([name, url, 'custom']);
        }
      }

      // Sort alphabetically
      rows.sort((a, b) => a[0].localeCompare(b[0]));

      console.log(`\nTotal shortcuts: ${rows.length}`);
      printTable(rows);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Command: openapp search <query>
program
  .command('search <query...>')
  .description('Open a Google search for the given query')
  .option('-i, --incognito', 'Open in incognito/private mode')
  .option('-e, --engine <engine>', 'Search engine to use (google, bing, duckduckgo)', 'google')
  .action(async (queryParts, options) => {
    try {
      const query = queryParts.join(' ').trim();

      if (!query) {
        console.error('Error: Search query cannot be empty.');
        process.exit(1);
      }

      // Validate query length (prevent extremely long queries)
      if (query.length > 500) {
        console.error('Error: Search query is too long (max 500 characters).');
        process.exit(1);
      }

      const searchEngines = {
        google: 'https://www.google.com/search?q=',
        bing: 'https://www.bing.com/search?q=',
        duckduckgo: 'https://duckduckgo.com/?q='
      };

      const engine = options.engine.toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(searchEngines, engine)) {
        console.error(`Error: Unknown search engine "${options.engine}". Supported: google, bing, duckduckgo`);
        process.exit(1);
      }

      // Properly encode the search query
      const encodedQuery = encodeURIComponent(query);
      const searchUrl = searchEngines[engine] + encodedQuery;

      console.log(`Searching for "${query}" on ${engine}...`);
      await openUrl(searchUrl, { incognito: options.incognito });
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Command: openapp config
const configCommand = program
  .command('config')
  .description('Configure openapp settings');

// Subcommand: openapp config browser <browser>
configCommand
  .command('browser <browser>')
  .description('Set the default browser (chrome, firefox, safari, edge, brave, opera, default)')
  .action((browser) => {
    try {
      const validatedBrowser = validateBrowser(browser);
      const config = loadConfig();
      config.settings.browser = validatedBrowser;
      saveConfig(config);

      if (validatedBrowser === 'default') {
        console.log('Default browser set to: system default');
      } else {
        console.log(`Default browser set to: ${validatedBrowser}`);
      }
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Subcommand: openapp config show
configCommand
  .command('show')
  .description('Show current configuration')
  .action(() => {
    try {
      const config = loadConfig();
      console.log('\nCurrent Configuration:');
      console.log('-'.repeat(40));
      console.log(`Browser: ${config.settings.browser}`);
      console.log(`Config file: ${CONFIG_FILE}`);
      console.log(`Custom shortcuts: ${Object.keys(config.customShortcuts).length}`);
      console.log('-'.repeat(40) + '\n');
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Subcommand: openapp config reset
configCommand
  .command('reset')
  .description('Reset configuration to defaults (removes all custom shortcuts)')
  .action(() => {
    try {
      const defaultConfig = {
        customShortcuts: {},
        settings: {
          browser: 'default'
        }
      };
      saveConfig(defaultConfig);
      console.log('Configuration reset to defaults.');
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

// Parse command line arguments
program.parse();
