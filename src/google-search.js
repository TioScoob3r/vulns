import axios from 'axios';
import * as cheerio from 'cheerio';
import fs from 'fs/promises';
import { CONFIG } from './config.js';
import { delay, validateUrl, formatTimestamp, sanitizeFilename } from './utils.js';
import { urlStore } from './url-store.js';

/**
 * @typedef {Object} GoogleSearchConfig
 * @property {number} searchDelay - Atraso entre buscas (ms).
 * @property {number} maxPages - Máximo de páginas de resultados a buscar.
 * @property {string} [outputFile] - Arquivo para salvar URLs encontradas (opcional).
 * @property {number} maxRetries - Máximo de tentativas em caso de erro.
 * @property {Object} [proxy] - Configuração de proxy (ex.: { host: string, port: number }).
 */

/** Configurações padrão da busca no Google */
const DEFAULT_CONFIG = {
  searchDelay: CONFIG.googleSearchDelay || 5000,
  maxPages: 1,
  outputFile: null,
  maxRetries: 3,
  proxy: null
};

/**
 * @typedef {Object} Messages
 * @property {string} searchingDork - Mensagem ao buscar um dork.
 * @property {string} foundUrls - Mensagem ao encontrar URLs únicas.
 * @property {string} rateLimitDetected - Mensagem ao detectar limite de taxa.
 * @property {string} searchFailed - Mensagem ao falhar na busca.
 * @property {string} maxRetriesReached - Mensagem ao atingir máximo de tentativas.
 * @property {string} waitingSearch - Mensagem de espera antes da próxima busca.
 * @property {string} resultsSaved - Mensagem ao salvar resultados.
 * @property {string} errorSavingResults - Mensagem de erro ao salvar resultados.
 */

/** Mensagens em português */
const MESSAGES = {
  searchingDork: 'Buscando pelo dork: %s',
  foundUrls: 'Encontradas %d novas URLs únicas',
  rateLimitDetected: 'Limite de taxa do Google detectado. Aguardando %d segundos...',
  searchFailed: 'Tentativa de busca %d falhou: %s',
  maxRetriesReached: 'Máximo de tentativas atingido para o dork: %s',
  waitingSearch: 'Aguardando %d segundos antes da próxima busca no Google...',
  resultsSaved: 'Resultados da busca salvos em %s',
  errorSavingResults: 'Erro ao salvar resultados da busca: %s'
};

/**
 * Registra logs com nível e timestamp.
 * @param {string} level - Nível do log (INFO, WARN, ERROR).
 * @param {string} message - Mensagem do log.
 */
function log(level, message) {
  console.log(`[${formatTimestamp()}] [${level}] ${message}`);
}

/**
 * Realiza uma busca no Google usando um dork e retorna URLs únicas.
 * @param {string} dork - Dork de busca no Google.
 * @param {Partial<GoogleSearchConfig>} [config] - Configurações opcionais.
 * @returns {Promise<string[]>} Lista de URLs únicas encontradas.
 */
export async function searchGoogle(dork, config = {}) {
  // Aviso ético
  log('WARN', 'AVISO: Buscas automatizadas no Google devem cumprir os termos de serviço. Use apenas em testes autorizados.');

  const searchConfig = { ...DEFAULT_CONFIG, ...config };
  const sanitizedDork = encodeURIComponent(dork.trim());
  let allUrls = new Set();
  let retries = 0;

  log('INFO', MESSAGES.searchingDork.replace('%s', dork));

  while (retries < searchConfig.maxRetries) {
    try {
      for (let page = 0; page < searchConfig.maxPages; page++) {
        const urls = await searchGooglePage(sanitizedDork, page * 10, searchConfig);
        urls.forEach(url => allUrls.add(url));
        if (urls.length === 0 || page === searchConfig.maxPages - 1) break;
        await delay(searchConfig.searchDelay);
      }

      const uniqueUrls = Array.from(allUrls).filter(url => {
        const isValid = validateUrl(url);
        const isTested = urlStore.isUrlTested(url);
        if (isValid && !isTested) {
          urlStore.markUrlAsTested(url);
          return true;
        }
        return false;
      });

      log('INFO', MESSAGES.foundUrls.replace('%d', uniqueUrls.length));

      if (searchConfig.outputFile) {
        await saveResults(uniqueUrls, searchConfig.outputFile);
      }

      return uniqueUrls;
    } catch (error) {
      retries++;
      if (error.response?.status === 429) {
        log('WARN', MESSAGES.rateLimitDetected.replace('%d', searchConfig.searchDelay * 2 / 1000));
        await delay(searchConfig.searchDelay * 2);
      } else {
        log('ERROR', MESSAGES.searchFailed.replace('%d', retries).replace('%s', error.message));
        if (retries >= searchConfig.maxRetries) {
          log('ERROR', MESSAGES.maxRetriesReached.replace('%s', dork));
          return [];
        }
        await delay(searchConfig.searchDelay);
      }
    }
  }

  return [];
}

/**
 * Busca uma página específica de resultados do Google.
 * @param {string} dork - Dork de busca codificado.
 * @param {number} start - Índice de início dos resultados.
 * @param {GoogleSearchConfig} config - Configurações da busca.
 * @returns {Promise<string[]>} URLs encontradas na página.
 */
async function searchGooglePage(dork, start, config) {
  const now = Date.now();
  if (lastSearchTime && now - lastSearchTime < config.searchDelay) {
    const waitTime = config.searchDelay - (now - lastSearchTime);
    log('INFO', MESSAGES.waitingSearch.replace('%d', waitTime / 1000));
    await delay(waitTime);
  }

  const url = `https://www.google.com/search?q=${dork}&start=${start}`;
  try {
    const axiosConfig = {
      headers: CONFIG.headers,
      timeout: CONFIG.timeoutMs || 10000,
      proxy: config.proxy || null
    };
    const response = await axios.get(url, axiosConfig);

    lastSearchTime = Date.now();

    const $ = cheerio.load(response.data);
    const urls = new Set();

    $('a').each((_, element) => {
      const href = $(element).attr('href');
      if (href?.startsWith('/url?q=')) {
        const cleanUrl = href.replace('/url?q=', '').split('&')[0];
        if (validateUrl(cleanUrl) && !cleanUrl.includes('google.com') && cleanUrl.includes('=')) {
          urls.add(decodeURIComponent(cleanUrl));
        }
      }
    });

    return Array.from(urls);
  } catch (error) {
    throw error; // Propaga erro para ser tratado pelo chamador
  }
}

/**
 * Salva URLs encontradas em um arquivo JSON.
 * @param {string[]} urls - Lista de URLs.
 * @param {string} outputFile - Nome do arquivo de saída.
 */
async function saveResults(urls, outputFile) {
  try {
    const sanitizedFile = sanitizeFilename(outputFile);
    const data = {
      timestamp: formatTimestamp(),
      totalUrls: urls.length,
      urls
    };
    await fs.writeFile(sanitizedFile, JSON.stringify(data, null, 2));
    log('INFO', MESSAGES.resultsSaved.replace('%s', sanitizedFile));
  } catch (error) {
    log('ERROR', MESSAGES.errorSavingResults.replace('%s', error.message));
  }
}

/** Último momento de busca no Google */
let lastSearchTime = 0;