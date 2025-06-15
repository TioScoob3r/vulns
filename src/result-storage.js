import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// Helper para obter o diretório do módulo atual em ES Modules
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Gerencia o armazenamento de resultados de varreduras em arquivos JSON.
 * Utiliza um método estático `create` para inicialização assíncrona.
 */
export class ResultStorage {
  // Constantes de caminho como membros estáticos privados para melhor encapsulamento
  static #RESULTS_DIR = path.join(__dirname, '..', 'results');

  // Construtor privado para forçar o uso do método de fábrica `create`
  private constructor() {}

  /**
   * Cria e inicializa uma instância de ResultStorage.
   * Garante que o diretório de resultados exista antes de retornar a instância.
   * @returns {Promise<ResultStorage>} Uma instância pronta para uso.
   */
  public static async create() {
    const instance = new ResultStorage();
    try {
      await fs.mkdir(this.#RESULTS_DIR, { recursive: true });
      console.log(`[+] Diretório de resultados garantido em: ${this.#RESULTS_DIR}`);
    } catch (error) {
      console.error('[-] Falha crítica ao criar o diretório de resultados:', error.message);
      // Lançar o erro impede que a aplicação continue em um estado instável
      throw error;
    }
    return instance;
  }

  /**
   * Salva os detalhes de uma URL vulnerável em um arquivo JSON específico do domínio.
   * @param {string} url - A URL vulnerável encontrada.
   * @param {object} result - O objeto com os detalhes da vulnerabilidade.
   */
  public async saveVulnerableUrl(url, result) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.replace(/[^a-z0-9.-]/gi, '_'); // Sanitiza o nome do domínio
      const timestamp = new Date();
      const filename = `${timestamp.toISOString().replace(/[:.]/g, '-')}_vulnerability.json`;

      const domainDir = path.join(ResultStorage.#RESULTS_DIR, domain);
      const filepath = path.join(domainDir, filename);

      // Garante que o subdiretório do domínio exista
      await fs.mkdir(domainDir, { recursive: true });

      const data = {
        url,
        timestamp: timestamp.toISOString(),
        columns: result.columns,
        tables: Array.from(result.tables), // Converte Set para Array, se aplicável
        successfulPayloads: result.successfulPayloads,
      };

      await this.#writeJsonFile(filepath, data);
      console.log(`[+] Detalhes da vulnerabilidade salvos em: ${filepath}`);
    } catch (error) {
      // Captura erros de URL inválida ou de escrita de arquivo
      console.error(`[-] Erro ao salvar resultado para a URL "${url}": ${error.message}`);
    }
  }

  /**
   * Salva um resumo completo da varredura.
   * @param {object} stats - Estatísticas da varredura.
   * @param {Map<string, object>} vulnerableUrls - Um Map das URLs vulneráveis e seus detalhes.
   */
  public async saveScanSummary(stats, vulnerableUrls) {
    const timestamp = new Date();
    const summaryPath = path.join(ResultStorage.#RESULTS_DIR, `scan_summary_${timestamp.toISOString().replace(/[:.]/g, '-')}.json`);

    const summary = {
      timestamp: timestamp.toISOString(),
      stats,
      // Converte o Map para um array de objetos para serialização JSON
      vulnerableUrls: Array.from(vulnerableUrls.entries()).map(([url, details]) => ({
        url,
        ...details,
      })),
    };

    try {
      await this.#writeJsonFile(summaryPath, summary);
      console.log(`[+] Resumo da varredura salvo em: ${summaryPath}`);
    } catch (error) {
      console.error(`[-] Erro ao salvar o resumo da varredura: ${error.message}`);
    }
  }

  /**
   * Helper privado para escrever objetos em arquivos JSON formatados.
   * @param {string} filepath - O caminho completo do arquivo.
   * @param {object} data - O objeto a ser serializado e salvo.
   */
  async #writeJsonFile(filepath, data) {
    // O re-lançamento do erro permite que o chamador decida como lidar com a falha
    try {
      await fs.writeFile(filepath, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error(`[-] Falha ao escrever o arquivo JSON em ${filepath}`);
      throw error;
    }
  }
}