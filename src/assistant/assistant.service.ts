import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConversationLog } from './entities/conversation-log.entity';
import { WazuhService } from '../wazuh/wazuh.service';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { ChatRequestDto } from './dto/chat-request.dto';
import { randomUUID } from 'crypto';
import { BlacklistService } from '../firewall/blacklist.service';
import { WhitelistService } from '../firewall/whitelist.service';
import { BlockSource } from '../firewall/entities/blacklist-entry.entity';

@Injectable()
export class AssistantService {
  private genAI: GoogleGenerativeAI;
  private modelName: string;

  constructor(
    @InjectRepository(ConversationLog)
    private readonly conversationLogRepo: Repository<ConversationLog>,
    private readonly wazuhService: WazuhService,
    private readonly blacklistService: BlacklistService,
    private readonly whitelistService: WhitelistService,
  ) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.warn('GEMINI_API_KEY is not defined in environment variables.');
    }
    this.genAI = new GoogleGenerativeAI(apiKey || 'missing-key');
    this.modelName = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
  }

  private getSystemPrompt(isSummaryRequest: boolean = false): string {
    if (isSummaryRequest) {
      return `
Tu es un assistant SOC expert. RÈGLES :
- Fournis une analyse claire, professionnelle et synthétique du résumé des alertes du jour en 3 à 5 lignes.
- Ne commence pas par des formules de politesse ("Bonjour", etc.).
- Explique la sévérité des alertes et les actions potentielles à entreprendre de manière concise.
- Contexte : Suricata (alert= détecte, drop= bloque), Wazuh. Ne jamais inventer de données.
`;
    }
    return `
Tu es un assistant SOC expert. RÈGLES STRICTES :
- Réponds en 1 à 3 lignes MAXIMUM. Pas d'exceptions.
- Pas de "Bonjour", "Bien sûr", "Absolument", ou autres formules.
- Pas de listes à puces. Pas de paragraphes multiples.
- Une seule réponse directe et concise.
- Si besoin de détails, demande "Plus de détails ?"

Contexte : Suricata (alert= détecte, drop= bloque), Wazuh. Ne jamais inventer de données.
`;
  }

  private async fetchAlertContext(alertId: string): Promise<string> {
    try {
      let alert: any = null;

      try {
        // Query indexer by ID directly first (rule.id or document _id)
        const directAlerts = await this.wazuhService.fetchRecentAlerts({ id: alertId, limit: 1 });
        if (directAlerts && directAlerts.length > 0) {
          alert = directAlerts[0];
        }
      } catch (directError) {
        console.warn(`[Assistant] Direct alert query failed for ID ${alertId}:`, directError.message);
      }

      if (!alert) {
        // Fallback: search in the recent 1000 alerts
        const alerts = await this.wazuhService.fetchRecentAlerts({ limit: 1000 });
        alert = alerts.find(a => a.rule?.id === alertId || a.id === alertId);
      }
      
      if (!alert) {
        return `Aucun détail supplémentaire trouvé pour l'alerte ID ${alertId}.`;
      }

      return `
Voici les données d'une alerte de sécurité détectée par Suricata/Wazuh :

Signature : ${alert.rule?.description || 'N/A'}
Sévérité : ${alert.rule?.level || 'N/A'}
Catégorie : ${alert.rule?.groups?.join(', ') || 'N/A'}
IP source : ${alert.data?.src_ip || 'N/A'}
IP destination : ${alert.data?.dest_ip || 'N/A'}
Port destination : ${alert.data?.dest_port || 'N/A'}
Protocole : ${alert.data?.protocol || 'N/A'}
Horodatage : ${alert.timestamp || 'N/A'}
Agent : ${alert.agent?.name || 'N/A'}
`;
    } catch (e) {
      console.error(e);
      return `Impossible de récupérer le contexte additionnel pour l'alerte ${alertId}.`;
    }
  }

  private normalizeText(text: string): string {
    return text
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim();
  }

  private extractIpv4s(text: string): string[] {
    const matches = text.match(/\b((?:\d{1,3}\.){3}\d{1,3})\b/g) || [];
    return [...new Set(matches.filter((ip) => this.isValidIpv4(ip)))];
  }

  private isValidIpv4(ip: string): boolean {
    const parts = ip.split('.').map((part) => Number(part));
    return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255);
  }

  private isAffirmativeMessage(message: string): boolean {
    const text = this.normalizeText(message);
    return /\b(oui|yes|yep|ok|okay|daccord|d accord|confirm|confirme|go|proceed|all of them|all them|allez|vas y|tout|tous)\b/.test(text);
  }

  private detectBulkPurgeTarget(message: string): 'blacklist' | 'whitelist' | null {
    const text = this.normalizeText(message);
    const wantsBulk = /\b(all|all of them|all the ip|all the ips|every ip|every ips|everything|remove all|delete all|clear all|purge|empty|vider|effacer|supprimer tout|tout|tous)\b/.test(text);
    if (!wantsBulk) return null;

    if (/\b(blacklist|black list|liste noire)\b/.test(text)) return 'blacklist';
    if (/\b(whitelist|white list|liste blanche|allowlist)\b/.test(text)) return 'whitelist';
    return null;
  }

  private detectPendingBulkPurge(history: ConversationLog[], message: string): 'blacklist' | 'whitelist' | null {
    if (!this.isAffirmativeMessage(message)) return null;
    if (history.length < 1) return null;

    const lastEntry = history[history.length - 1];
    const assistantAskedForConfirmation = /confirmez|confirmer|confirm|purge globale|vider toute|vider la liste|supprimer toute|clear the|purge the/i.test(lastEntry.aiReply || '');
    if (!assistantAskedForConfirmation) return null;

    return this.detectBulkPurgeTarget(lastEntry.userMessage);
  }

  private parseFirewallCommand(message: string): {
    ips: string[];
    action: 'block' | 'unblock' | 'whitelist-add' | 'whitelist-remove' | 'remove-generic';
  } | null {
    const ips = this.extractIpv4s(message);
    const text = this.normalizeText(message);
    const hasFirewallIntent = /\b(blacklist|black list|liste noire|whitelist|white list|liste blanche|allowlist|block|blocker|ban|unblock|unban|bloquer|bloque|bloquez|debloquer|remove|delete|retire|supprime|add|ajouter|ajoute|whitelist|autoriser|trust|retirer|enlever)\b/.test(text);

    if (ips.length === 0) {
      return hasFirewallIntent ? { ips: [], action: 'remove-generic' } : null;
    }

    if (!hasFirewallIntent) {
      return null;
    }

    const hasBlacklistWord = /\b(blacklist|black list|liste noire|block|ban|unblock|unban|bloquer|bloque|debloquer|retirer de la liste noire|supprimer de la liste noire)\b/.test(text);
    const hasWhitelistWord = /\b(whitelist|white list|liste blanche|allowlist|allow|trust|unwhitelist|whitelisting|autoriser|ajouter a la liste blanche|retirer de la liste blanche|supprimer de la liste blanche)\b/.test(text);
    const hasAddWord = /\b(add|ajouter|ajoute|mettre|put|create|insert)\b/.test(text);
    const hasRemoveWord = /\b(remove|delete|del|retire|supprime|drop|unblock|retirer|enlever)\b/.test(text);

    if (/\b(unblock|unban|debloquer|retirer de la liste noire|supprimer de la liste noire)\b/.test(text)) {
      return { ips, action: 'unblock' };
    }

    if (hasRemoveWord && hasWhitelistWord) {
      return { ips, action: 'whitelist-remove' };
    }

    if (hasRemoveWord && hasBlacklistWord) {
      return { ips, action: 'unblock' };
    }

    if (/\b(block|blocker|ban|bloquer|bloque|bloquez)\b/.test(text) || (hasAddWord && hasBlacklistWord)) {
      return { ips, action: 'block' };
    }

    if (/\b(remove from whitelist|unwhitelist|retirer de la liste blanche|supprimer de la liste blanche|delete from whitelist)\b/.test(text)) {
      return { ips, action: 'whitelist-remove' };
    }

    if (/\b(add to whitelist|liste blanche|allowlist|autoriser|trust)\b/.test(text) || (hasAddWord && hasWhitelistWord)) {
      return { ips, action: 'whitelist-add' };
    }

    if (hasRemoveWord) {
      return { ips, action: 'remove-generic' };
    }

    return null;
  }

  private async executeBulkPurge(
    userId: number,
    username: string,
    listName: 'blacklist' | 'whitelist',
  ): Promise<{ reply: string; ips: string[] }> {
    if (listName === 'blacklist') {
      const ips = await this.blacklistService.purgeAll(userId, username);
      return {
        reply: ips.length > 0
          ? `${ips.length} IP${ips.length > 1 ? 's' : ''} retirée${ips.length > 1 ? 's' : ''} de la blacklist.`
          : 'La blacklist est déjà vide.',
        ips,
      };
    }

    const ips = await this.whitelistService.purgeAll(userId, username);
    return {
      reply: ips.length > 0
        ? `${ips.length} IP${ips.length > 1 ? 's' : ''} retirée${ips.length > 1 ? 's' : ''} de la whitelist.`
        : 'La whitelist est déjà vide.',
      ips,
    };
  }

  private async handleFirewallCommand(userId: number, username: string, message: string): Promise<{ reply: string; ips: string[] } | null> {
    const command = this.parseFirewallCommand(message);
    if (!command) return null;

    const { ips, action } = command;
    if (ips.length === 0) {
      return {
        reply: "Donnez-moi une ou plusieurs adresses IP à traiter, par exemple: block 192.168.101.130 ou remove 192.168.101.130 192.168.101.153.",
        ips: [],
      };
    }

    const affectedIps = new Set<string>();
    const markAffected = (ip: string) => affectedIps.add(ip);

    switch (action) {
      case 'block': {
        for (const ip of ips) {
          if (await this.whitelistService.isWhitelisted(ip)) {
            await this.whitelistService.remove(ip, userId, username);
          }
          const reason = `Bloqué via assistant: ${message}`;
          await this.blacklistService.block(ip, reason, BlockSource.MANUAL, userId, username);
          markAffected(ip);
        }
        return { reply: `${ips.length > 1 ? 'IPs' : 'IP'} ${ips.join(', ')} ajoutée${ips.length > 1 ? 's' : ''} à la blacklist.`, ips: [...affectedIps] };
      }
      case 'unblock': {
        for (const ip of ips) {
          await this.blacklistService.unblock(ip, userId, username);
          markAffected(ip);
        }
        return { reply: `${ips.length > 1 ? 'IPs' : 'IP'} ${ips.join(', ')} retirée${ips.length > 1 ? 's' : ''} de la blacklist.`, ips: [...affectedIps] };
      }
      case 'whitelist-add': {
        for (const ip of ips) {
          if (await this.blacklistService.isBlacklisted(ip)) {
            await this.blacklistService.unblock(ip, userId, username);
          }
          await this.whitelistService.add(ip, `Ajoutée via assistant: ${message}`, userId, username);
          markAffected(ip);
        }
        return { reply: `${ips.length > 1 ? 'IPs' : 'IP'} ${ips.join(', ')} ajoutée${ips.length > 1 ? 's' : ''} à la whitelist.`, ips: [...affectedIps] };
      }
      case 'whitelist-remove': {
        for (const ip of ips) {
          await this.whitelistService.remove(ip, userId, username);
          markAffected(ip);
        }
        return { reply: `${ips.length > 1 ? 'IPs' : 'IP'} ${ips.join(', ')} retirée${ips.length > 1 ? 's' : ''} de la whitelist.`, ips: [...affectedIps] };
      }
      case 'remove-generic': {
        const removedFromBlacklist: string[] = [];
        const removedFromWhitelist: string[] = [];

        for (const ip of ips) {
          if (await this.blacklistService.isBlacklisted(ip)) {
            await this.blacklistService.unblock(ip, userId, username);
            removedFromBlacklist.push(ip);
            markAffected(ip);
            continue;
          }

          if (await this.whitelistService.isWhitelisted(ip)) {
            await this.whitelistService.remove(ip, userId, username);
            removedFromWhitelist.push(ip);
            markAffected(ip);
          }
        }

        if (removedFromBlacklist.length > 0 && removedFromWhitelist.length === 0) {
          return { reply: `${removedFromBlacklist.length > 1 ? 'IPs' : 'IP'} ${removedFromBlacklist.join(', ')} retirée${removedFromBlacklist.length > 1 ? 's' : ''} de la blacklist.`, ips: [...affectedIps] };
        }

        if (removedFromWhitelist.length > 0 && removedFromBlacklist.length === 0) {
          return { reply: `${removedFromWhitelist.length > 1 ? 'IPs' : 'IP'} ${removedFromWhitelist.join(', ')} retirée${removedFromWhitelist.length > 1 ? 's' : ''} de la whitelist.`, ips: [...affectedIps] };
        }

        if (removedFromBlacklist.length > 0 || removedFromWhitelist.length > 0) {
          return {
            reply: `${[...removedFromBlacklist, ...removedFromWhitelist].length > 1 ? 'IPs' : 'IP'} ${[...removedFromBlacklist, ...removedFromWhitelist].join(', ')} retirée${[...removedFromBlacklist, ...removedFromWhitelist].length > 1 ? 's' : ''} des listes.`,
            ips: [...affectedIps],
          };
        }

        return { reply: `Je n'ai trouvé aucune entrée pour ${ips.join(', ')} dans la blacklist ou la whitelist.`, ips: [] };
      }
      default:
        return null;
    }
  }

  async chat(userId: number, username: string, dto: ChatRequestDto) {
    const conversationId = dto.conversationId || randomUUID();
    const history = dto.conversationId ? await this.conversationLogRepo.find({
      where: { conversationId: dto.conversationId },
      order: { createdAt: 'ASC' },
    }) : [];

    const confirmedBulkTarget = this.detectPendingBulkPurge(history, dto.message);
    if (confirmedBulkTarget) {
      const bulkReply = await this.executeBulkPurge(userId, username, confirmedBulkTarget);
      const log = this.conversationLogRepo.create({
        userId,
        alertId: dto.alertId,
        userMessage: dto.message,
        aiReply: bulkReply.reply,
        conversationId,
      });
      await this.conversationLogRepo.save(log);
      return { reply: bulkReply.reply, conversationId, mutation: { type: 'ip-list-changed', ips: bulkReply.ips } };
    }

    const bulkTarget = this.detectBulkPurgeTarget(dto.message);
    if (bulkTarget) {
      const prompt = bulkTarget === 'blacklist'
        ? 'Voulez-vous vraiment purger toute la blacklist ? Répondez oui pour confirmer.'
        : 'Voulez-vous vraiment purger toute la whitelist ? Répondez oui pour confirmer.';

      const log = this.conversationLogRepo.create({
        userId,
        alertId: dto.alertId,
        userMessage: dto.message,
        aiReply: prompt,
        conversationId,
      });
      await this.conversationLogRepo.save(log);
      return { reply: prompt, conversationId };
    }

    const firewallReply = await this.handleFirewallCommand(userId, username, dto.message);

    if (firewallReply) {
      const log = this.conversationLogRepo.create({
        userId,
        alertId: dto.alertId,
        userMessage: dto.message,
        aiReply: firewallReply.reply,
        conversationId,
      });
      await this.conversationLogRepo.save(log);
      return { reply: firewallReply.reply, conversationId, mutation: { type: 'ip-list-changed', ips: firewallReply.ips } };
    }
    
    let alertId = dto.alertId;
    if (!alertId && dto.message) {
      // Find alert IDs: typically 15-30 character alphanumeric strings (can contain dashes and underscores)
      const match = dto.message.match(/(?:^|\s)([a-zA-Z0-9_-]{15,30})(?=$|\s|[.,;:?!])/);
      if (match) {
        alertId = match[1];
      } else {
        // Look for 4 to 6 digit rule ID
        const ruleMatch = dto.message.match(/\b(?:rule|alert|alerte|id|règle)\s*[:#]?\s*(\d{4,6})\b/i) ||
                          dto.message.match(/\b(\d{4,6})\b/);
        if (ruleMatch) {
          alertId = ruleMatch[1];
        }
      }
    }

    const isSummaryRequest = dto.message.toLowerCase().includes('résumé du jour') || 
                             dto.message.toLowerCase().includes('daily summary') || 
                             dto.message.toLowerCase().includes('sévérité');
    let prompt = this.getSystemPrompt(isSummaryRequest) + '\n\n';
    
    if (alertId) {
      const context = await this.fetchAlertContext(alertId);
      prompt += context + '\n\n';
    }

    if (dto.conversationId) {
       history.forEach(log => {
           prompt += `Utilisateur: ${log.userMessage}\n`;
           prompt += `Assistant: ${log.aiReply}\n`;
       });
    }

    prompt += `Utilisateur: ${dto.message}\nAssistant:`;

    try {
      const model = this.genAI.getGenerativeModel({ model: this.modelName });
      const result = await model.generateContent(prompt);
      const reply = result.response.text();

      const log = this.conversationLogRepo.create({
        userId,
        alertId,
        userMessage: dto.message,
        aiReply: reply,
        conversationId,
      });
      await this.conversationLogRepo.save(log);

      return { reply, conversationId };
    } catch (error) {
      console.error('Error calling Gemini API:', error);
      throw new InternalServerErrorException('Erreur lors de la communication avec le service IA');
    }
  }

  async getHistory(conversationId: string) {
    return this.conversationLogRepo.find({
      where: { conversationId },
      order: { createdAt: 'ASC' }
    });
  }

  async getQuickAnalysis(userId: number, alertId: string) {
    const context = await this.fetchAlertContext(alertId);

    const prompt = `
${context}

Réponds STRICTEMENT dans ce format JSON, sans texte avant ou après :
{
  "summary": "résumé en 2-3 phrases de ce qui s'est passé et de sa gravité",
  "investigationSteps": ["étape 1", "étape 2", "étape 3"],
  "remediationSteps": ["action 1", "action 2"]
}
`;

    try {
      const model = this.genAI.getGenerativeModel({ model: this.modelName });
      const result = await model.generateContent(prompt);
      let text = result.response.text().trim();

      if (text.startsWith('\`\`\`json')) {
         text = text.substring(7, text.length - 3).trim();
      } else if (text.startsWith('\`\`\`')) {
         text = text.substring(3, text.length - 3).trim();
      }

      const parsed = JSON.parse(text);
      return parsed;
    } catch (error) {
      console.error('Error getting quick analysis:', error);
      return {
         summary: "Impossible de générer l'analyse. Vérifiez les logs.",
         investigationSteps: [],
         remediationSteps: []
      };
    }
  }

  async getLatestAlert() {
    try {
      const alerts = await this.wazuhService.fetchRecentAlerts({ limit: 1 });
      return alerts[0] || null;
    } catch (error) {
      console.error('Error fetching latest alert:', error);
      return null;
    }
  }

  async getDailySummary() {
    try {
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);
      const stats = await this.wazuhService.getAlertStats({
        startDate: todayStart.toISOString()
      });
      return stats;
    } catch (error) {
      console.error('Error fetching daily summary:', error);
      return { totalAlerts: 0, severityDistribution: {}, attacksByType: {}, topSourceIps: [], alertsOverTime: [] };
    }
  }
}
