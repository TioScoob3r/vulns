/**
 * Adiciona um atraso em milissegundos.
 * @param {number} ms - Tempo em milissegundos.
 * @returns {Promise<void>} Promessa resolvida após o atraso.
 */
export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Sanitiza um nome de arquivo, substituindo caracteres inválidos por sublinhados.
 * @param {string} filename - Nome do arquivo a sanitizar.
 * @returns {string} Nome do arquivo sanitizado.
 */
export function sanitizeFilename(filename) {
  return filename.replace(/[^a-zA-Z0-9]/g, '_');
}

/**
 * Formata a data atual como uma string no formato ISO, substituindo caracteres inválidos.
 * @returns {string} Timestamp formatado (ex.: 2025-06-15T17-43-00).
 */
export function formatTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

/**
 * Extrai o domínio de uma URL.
 * @param {string} url - URL a ser processada.
 * @returns {string | null} Domínio extraído ou null se a URL for inválida.
 */
export function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Sanitiza payloads para evitar erros de sintaxe.
 * @param {string} payload - Payload a sanitizar.
 * @param {number} [maxLength=1000] - Tamanho máximo do payload.
 * @returns {string} Payload sanitizado.
 * @throws {Error} Se o payload não for uma string ou exceder o tamanho máximo.
 */
export function sanitizePayload(payload, maxLength = 1000) {
  if (typeof payload !== 'string') {
    throw new Error('Payload must be a string');
  }
  if (payload.length > maxLength) {
    throw new Error(`Payload exceeds maximum length of ${maxLength} characters`);
  }
  return payload.replace(/[\r\n;]/g, '').trim();
}

/**
 * Valida uma URL.
 * @param {string} url - URL a ser validada.
 * @returns {boolean} True se a URL for válida, false caso contrário.
 */
export function validateUrl(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}