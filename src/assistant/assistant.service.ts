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
Tu es un assistant expert en cybersécurité intégré à une plateforme IDS/IPS (Suricata + Wazuh) pour des analystes SOC.

RÈGLES ABSOLUES DE COMMUNICATION :
- Réponds en 3 à 6 lignes MAX. Sois direct, pas de blabla d'introduction.
- N'écris JAMAIS de phrases de bienvenue ou d'introduction (pas de "Bonjour", "Absolument", "Bien sûr").
- Commence directement par la réponse.
- Utilise des listes à puces courtes quand c'est pertinent (max 4 items).
- Si la question nécessite plus de détails, dis "Tu veux plus de détails sur [point X] ?"

Contexte technique :
- Suricata : règles "alert" = détecte, règles "drop" = bloque
- Alertes : signature, sévérité (1=low, 2=medium, 3=high), IP src/dst, protocole, port
- Ne jamais inventer de données absentes de l'alerte
`;
  }

  private async fetchAlertContext(alertId: string): Promise<string> {
    try {
      // Pour une vraie implémentation, on pourrait filtrer par ID. 
      // Ici, on récupère les récentes et on cherche celle qui correspond, ou on utilise le système de requêtes wazuh.
      const alerts = await this.wazuhService.fetchRecentAlerts({ limit: 1000 });
      const alert = alerts.find(a => a.rule?.id === alertId || a.id === alertId);
      
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
    
    let prompt = this.getSystemPrompt() + '\n\n';
    
    if (dto.alertId) {
      const context = await this.fetchAlertContext(dto.alertId);
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
        alertId: dto.alertId,
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
}
