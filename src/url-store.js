import fs from 'fs/promises';
import { formatTimestamp, extractDomain, sanitizeFilename } from './utils.js';

/**
 * @typedef {Object} URLStoreConfig
 * @property {number} maxPathsPerDomain - Máximo de caminhos por domínio antes do rate limit.
 * @property {number} cooldownPeriod - Período de cooldown em milissegundos.
 * @property {string} [stateFile] - Arquivo para persistência do estado (opcional).
 */

/**
 * @typedef {Object} URLStoreStats
 * @property {number} totalTested - Total de URLs testadas.
 * @property {number} totalVulnerable - Total de URLs vulneráveis.
 * @property {number} uniqueDomains - Total de domínios únicos.
 * @property {number} recentlyTestedDomains - Domínios testados recentemente.
 */

/** Configurações padrão do URLStore */
const DEFAULT_CONFIG = {
  maxPathsPerDomain: 5,
  cooldownPeriod: 300000, // 5 minutos
  stateFile: null
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
 * Armazena e gerencia URLs testadas e vulneráveis.
 */
class URLStore {
  /**
   * @param {Partial<URLStoreConfig>} [config] - Configurações opcionais.
   */
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    /** @type {Set<string>} */
    this.testedUrls = new Set();
    /** @type {Map<string, string[]>} */
    this.vulnerableUrls = new Map();
    /** @type {Map<string, Set<string>>} */
    this.seenDomains = new Map();
    /** @type {Map<string, number>} */
    this.lastTestedTime = new Map();
    this.loadState().catch(err => log('ERROR', `Failed to load state: ${err.message}`));
  }

  /**
   * Normaliza uma URL, removendo parâmetros de rastreamento.
   * @param {string} url - URL a normalizar.
   * @returns {string} URL normalizada.
   */
  normalizeUrl(url) {
    try {
      const urlObj = new URL(url);
      ['utm_source', 'utm_medium', 'utm_campaign', 'ref', 'fbclid'].forEach(param => {
        urlObj.searchParams.delete(param);
      });
      return urlObj.origin + urlObj.pathname;
    } catch {
      log('WARN', `Invalid URL for normalization: ${url}`);
      return url;
    }
  }

  /**
   * Extrai o domínio de uma URL.
   * @param {string} url - URL a processar.
   * @returns {string | null} Domínio ou null se inválido.
   */
  getDomain(url) {
    const domain = extractDomain(url);
    if (!domain) {
      log('WARN', `Invalid URL for domain extraction: ${url}`);
    }
    return domain;
  }

  /**
   * Verifica se a URL já foi testada ou está em cooldown.
   * @param {string} url - URL a verificar.
   * @returns {boolean} True se a URL foi testada ou está em cooldown.
   */
  isUrlTested(url) {
    const normalizedUrl = this.normalizeUrl(url);
    const domain = this.getDomain(url);

    if (this.testedUrls.has(normalizedUrl)) {
      log('INFO', `URL already tested: ${normalizedUrl}`);
      return true;
    }

    if (domain && this.seenDomains.has(domain)) {
      const paths = this.seenDomains.get(domain);
      const urlPath = new URL(url).pathname;

      if (paths.size >= this.config.maxPathsPerDomain) {
        const lastTest = this.lastTestedTime.get(domain) || 0;
        const timeSinceLastTest = Date.now() - lastTest;

        if (timeSinceLastTest < this.config.cooldownPeriod) {
          log('INFO', `Skipping ${url} - Domain rate limited`);
          return true;
        } else {
          paths.clear();
          this.lastTestedTime.set(domain, Date.now());
        }
      }
    }

    return false;
  }

  /**
   * Marca uma URL como testada.
   * @param {string} url - URL a marcar.
   */
  markUrlAsTested(url) {
    const normalizedUrl = this.normalizeUrl(url);
    const domain = this.getDomain(url);

    this.testedUrls.add(normalizedUrl);

    if (domain) {
      if (!this.seenDomains.has(domain)) {
        this.seenDomains.set(domain, new Set());
      }
      this.seenDomains.get(domain).add(new URL(url).pathname);
      this.lastTestedTime.set(domain, Date.now());
      this.saveState().catch(err => log('ERROR', `Failed to save state: ${err.message}`));
    }
  }

  /**
   * Adiciona uma URL como vulnerável com o payload correspondente.
   * @param {string} url - URL vulnerável.
   * @param {string} payload - Payload que explorou a vulnerabilidade.
   */
  addVulnerableUrl(url, payload) {
    const normalizedUrl = this.normalizeUrl(url);
    if (!this.vulnerableUrls.has(normalizedUrl)) {
      this.vulnerableUrls.set(normalizedUrl, []);
    }
    if (!this.vulnerableUrls.get(normalizedUrl).includes(payload)) {
      this.vulnerableUrls.get(normalizedUrl).push(payload);
      log('INFO', `Marked ${normalizedUrl} as vulnerable with payload: ${payload}`);
      this.saveState().catch(err => log('ERROR', `Failed to save state: ${err.message}`));
    }
  }

  /**
   * Obtém estatísticas do armazenamento.
   * @returns {URLStoreStats} Estatísticas do URLStore.
   */
  getStats() {
    const recentlyTestedDomains = Array.from(this.lastTestedTime.entries())
      .filter(([_, time]) => Date.now() - time < this.config.cooldownPeriod)
      .length;

    return {
      totalTested: this.testedUrls.size,
      totalVulnerable: this.vulnerableUrls.size,
      uniqueDomains: this.seenDomains.size,
      recentlyTestedDomains
    };
  }

  /**
   * Limpa entradas antigas com base no cooldown.
   */
  async cleanupOldEntries() {
    const now = Date.now();
    for (const [domain, time] of this.lastTestedTime.entries()) {
      if (now - time > this.config.cooldownPeriod) {
        this.lastTestedTime.delete(domain);
        this.seenDomains.delete(domain);
      }
    }
    await this.saveState();
    log('INFO', 'Cleaned up old entries');
  }

  /**
   * Salva o estado do URLStore em disco, se configurado.
   * @private
   */
  async saveState() {
    if (!this.config.stateFile) return;

    const state = {
      testedUrls: Array.from(this.testedUrls),
      vulnerableUrls: Object.fromEntries(this.vulnerableUrls),
      seenDomains: Object.fromEntries(
        Array.from(this.seenDomains.entries()).map(([k, v]) => [k, Array.from(v)])
      ),
      lastTestedTime: Object.fromEntries(this.lastTestedTime)
    };

    try {
      await fs.writeFile(this.config.stateFile, JSON.stringify(state, null, 2));
      log('INFO', `State saved to ${this.config.stateFile}`);
    } catch (error) {
      log('ERROR', `Error saving state: ${error.message}`);
    }
  }

  /**
   * Carrega o estado do URLStore do disco, se configurado.
   * @private
   */
  async loadState() {
    if (!this.config.stateFile) return;

    try {
      const data = await fs.readFile(this.config.stateFile, 'utf-8');
      const state = JSON.parse(data);

      this.testedUrls = new Set(state.testedUrls || []);
      this.vulnerableUrls = new Map(Object.entries(state.vulnerableUrls || {}));
      this.seenDomains = new Map(
        Object.entries(state.seenDomains || {}).map(([k, v]) => [k, new Set(v)])
      );
      this.lastTestedTime = new Map(Object.entries(state.lastTestedTime || {}));
      log('INFO', `State loaded from ${this.config.stateFile}`);
    } catch (error) {
      log('WARN', `No state file found or invalid: ${error.message}`);
    }
  }
}

export const urlStore = new URLStore({
  stateFile: `url-store_${sanitizeFilename(formatTimestamp())}.json`
});