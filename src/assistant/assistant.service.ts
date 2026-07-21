import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConversationLog } from './entities/conversation-log.entity';
import { WazuhService } from '../wazuh/wazuh.service';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { ChatRequestDto } from './dto/chat-request.dto';
import { randomUUID } from 'crypto';

@Injectable()
export class AssistantService {
  private genAI: GoogleGenerativeAI;
  private modelName: string;

  constructor(
    @InjectRepository(ConversationLog)
    private readonly conversationLogRepo: Repository<ConversationLog>,
    private readonly wazuhService: WazuhService,
  ) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.warn('GEMINI_API_KEY is not defined in environment variables.');
    }
    this.genAI = new GoogleGenerativeAI(apiKey || 'missing-key');
    this.modelName = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  }

  private getSystemPrompt(): string {
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

  async chat(userId: number, dto: ChatRequestDto) {
    const conversationId = dto.conversationId || randomUUID();
    
    let alertId = dto.alertId;
    if (!alertId && dto.message) {
      // Find alert IDs: typically 15-30 character alphanumeric strings (like 2-i1hp8B0iudVhLN9xdA or lgKahp8B979vven6RxJ7)
      const match = dto.message.match(/\b([a-zA-Z0-9_-]{15,30})\b/);
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

    let prompt = this.getSystemPrompt() + '\n\n';
    
    if (alertId) {
      const context = await this.fetchAlertContext(alertId);
      prompt += context + '\n\n';
    }

    if (dto.conversationId) {
       const history = await this.conversationLogRepo.find({
           where: { conversationId: dto.conversationId },
           order: { createdAt: 'ASC' }
       });
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
