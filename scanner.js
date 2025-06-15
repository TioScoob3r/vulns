import { searchGoogle } from './src/google-search.js';
import { testSQLInjection } from './src/sql-injection.js';
import { isValidTestUrl } from './src/url-utils.js';
import { urlStore } from './src/url-store.js';
import { ResultStorage } from './src/result-storage.js';
import { CONFIG, DORK_PATTERNS } from './src/config.js';
import { delay, formatTimestamp } from './src/utils.js';

/**
 * @typedef {Object} Messages
 * @property {string} start - Mensagem de início do scanner.
 * @property {string} testingUrl - Mensagem ao testar uma URL.
 * @property {string} urlTested - Mensagem para URL já testada.
 * @property {string} vulnerabilityFound - Mensagem para vulnerabilidade confirmada.
 * @property {string} tablesFound - Mensagem para tabelas encontradas.
 * @property {string} columnsFound - Mensagem para colunas encontradas.
 * @property {string} searchingDork - Mensagem ao buscar um dork.
 * @property {string} waitingSearch - Mensagem de espera entre buscas.
 * @property {string} scanComplete - Mensagem de conclusão do scan.
 * @property {string} errorTestingUrl - Mensagem de erro ao testar URL.
 * @property {string} errorSearchingDork - Mensagem de erro ao buscar dork.
 * @property {string} errorDisplayingSummary - Mensagem de erro ao exibir resumo.
 */

/** Mensagens em português */
const MESSAGES = {
  start: '=== Iniciando Scanner de Vulnerabilidades de Injeção SQL ===',
  testingUrl: 'Testando URL: %s',
  urlTested: 'URL já testada: %s',
  vulnerabilityFound: 'Vulnerabilidade confirmada!',
  tablesFound: 'Tabelas do banco de dados encontradas:',
  columnsFound: 'Colunas encontradas:',
  searchingDork: 'Buscando por: %s',
  waitingSearch: 'Aguardando %d segundos antes da próxima busca...',
  scanComplete: '=== Escaneamento Concluído ===',
  errorTestingUrl: 'Erro ao testar URL: %s - %s',
  errorSearchingDork: 'Erro ao buscar dork: %s - %s',
  errorDisplayingSummary: 'Erro ao exibir resumo: %s'
};

/**
 * Registra logs com nível e timestamp.
 * @param {string} level - Nível do log (INFO, WARN, ERROR).
 * @param {string} message - Mensagem do log.
 */
function log(level, message) {
  console.log(`[${formatTimestamp()}] [${level}] ${message}`);
}

/** Instância de armazenamento de resultados */
const resultStorage = new ResultStorage();

/**
 * Processa uma única URL, testando-a para injeção SQL.
 * @param {string} url - URL a ser testada.
 * @param {number} testDelay - Atraso entre testes (ms).
 */
async function processSingleUrl(url, testDelay = 2000) {
  if (!isValidTestUrl(url)) {
    log('WARN', `URL inválida: ${url}`);
    return;
  }
  if (urlStore.isUrlTested(url)) {
    log('INFO', MESSAGES.urlTested.replace('%s', url));
    return;
  }

  log('INFO', MESSAGES.testingUrl.replace('%s', url));
  urlStore.markUrlAsTested(url);

  try {
    const result = await testSQLInjection(url);
    if (result.vulnerable) {
      await displayResults(result);
      await resultStorage.saveVulnerableUrl(url, result);
    }
  } catch (error) {
    log('ERROR', MESSAGES.errorTestingUrl.replace('%s', url).replace('%s', error.message));
  }

  await delay(testDelay);
}

/**
 * Exibe os resultados de uma URL vulnerável.
 * @param {Object} result - Resultado do teste de injeção SQL.
 */
async function displayResults(result) {
  log('WARN', MESSAGES.vulnerabilityFound);

  if (result.tables.size > 0) {
    log('INFO', MESSAGES.tablesFound);
    for (const table of result.tables) {
      console.log(`  - ${table}`);
    }
  }

  if (result.columns.length > 0) {
    log('INFO', MESSAGES.columnsFound);
    for (const column of result.columns) {
      console.log(`  - ${column}`);
    }
  }
}

/**
 * Exibe o resumo final do escaneamento em formato de tabela ASCII.
 */
async function displaySummary() {
  const stats = urlStore.getStats();
  log('INFO', MESSAGES.scanComplete);

  const table = [
    '+----------------------------------+-------+',
    '| Descrição                        | Valor |',
    '+----------------------------------+-------+',
    `| Total de URLs testadas           | ${stats.totalTested.toString().padStart(5)} |`,
    `| URLs vulneráveis encontradas     | ${stats.totalVulnerable.toString().padStart(5)} |`,
    `| Domínios únicos escaneados       | ${stats.uniqueDomains.toString().padStart(5)} |`,
    `| Domínios testados recentemente   | ${stats.recentlyTestedDomains.toString().padStart(5)} |`,
    '+----------------------------------+-------+'
  ].join('\n');

  console.log(table);
  await resultStorage.saveScanSummary(stats, urlStore.vulnerableUrls);
}

/**
 * Função principal que coordena o escaneamento.
 */
async function main() {
  // Aviso ético
  log('WARN', 'AVISO: Este scanner deve ser usado apenas em testes autorizados. O uso não autorizado é ilegal e antiético.');

  log('INFO', MESSAGES.start);

  for (const dork of DORK_PATTERNS) {
    log('INFO', MESSAGES.searchingDork.replace('%s', dork));
    try {
      const urls = await searchGoogle(dork, {
        maxPages: Math.ceil(CONFIG.maxResults / 10),
        searchDelay: CONFIG.googleSearchDelay,
        outputFile: `${CONFIG.outputDir}/search-${sanitizeFilename(dork)}.json`
      });
      for (const url of urls) {
        await processSingleUrl(url, CONFIG.testDelay || 2000);
      }
    } catch (error) {
      log('ERROR', MESSAGES.errorSearchingDork.replace('%s', dork).replace('%s', error.message));
    }

    log('INFO', MESSAGES.waitingSearch.replace('%d', CONFIG.googleSearchDelay / 1000));
    await delay(CONFIG.googleSearchDelay);
  }

  try {
    await displaySummary();
  } catch (error) {
    log('ERROR', MESSAGES.errorDisplayingSummary.replace('%s', error.message));
  }
}

main().catch(error => log('ERROR', `Erro crítico: ${error.message}`));