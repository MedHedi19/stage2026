import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  Content,
  FunctionCall,
  FunctionCallingMode,
  FunctionResponsePart,
  GoogleGenerativeAI,
} from '@google/generative-ai';
import { randomUUID } from 'crypto';
import { ConversationLog } from './entities/conversation-log.entity';
import { WazuhService } from '../wazuh/wazuh.service';
import { ChatRequestDto } from './dto/chat-request.dto';
import { BlacklistService } from '../firewall/blacklist.service';
import { WhitelistService } from '../firewall/whitelist.service';
import { FirewallHistoryService } from '../firewall/firewall-history.service';
import { ThreatIntelService } from '../firewall/threat-intel.service';
import { ThreatFeedScheduler } from '../firewall/threat-feed.scheduler';
import { FirewallListType } from '../firewall/entities/firewall-history.entity';
import { BlockSource } from '../firewall/entities/blacklist-entry.entity';
import { ReportType } from '../reports/report-types.enum';
import { UserRole } from '../users/entities/user.entity';
import {
  ASSISTANT_FUNCTION_DECLARATIONS,
  AssistantMutation,
  ReportParams,
  ToolExecutionContext,
} from './assistant.tools';

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
    private readonly firewallHistoryService: FirewallHistoryService,
    private readonly threatIntelService: ThreatIntelService,
    private readonly threatFeedScheduler: ThreatFeedScheduler,
  ) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.warn('GEMINI_API_KEY is not defined in environment variables.');
    }
    this.genAI = new GoogleGenerativeAI(apiKey || 'missing-key');
    this.modelName = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
  }

  private getSystemPrompt(language: string = 'fr'): string {
    const isFrench = language === 'fr';

    if (isFrench) {
      return `
Tu es l'assistant SOC interactif de SentinelOps. Tu aides les analystes à investiguer, réagir et documenter les incidents.

OUTILS DISPONIBLES (appelle-les selon l'intention, pas selon des mots-clés) :
- analyze_alert : analyser une alerte par ID (attaque réelle, faux positif, gravité, recommandations)
- get_daily_summary : statistiques opérationnelles du jour
- block_ip / unblock_ip : gestion de la blacklist
- add_to_whitelist / remove_from_whitelist : gestion de la whitelist
- purge_blacklist / purge_whitelist : vider une liste (confirmed=true seulement après confirmation explicite)
- get_firewall_history : historique des opérations blacklist/whitelist (qui a bloqué/débloqué, quand, pourquoi). Peut filtrer par liste (blacklist/whitelist) et limiter le nombre d'entrées.
- generate_report : exporter un rapport PDF/Excel (types : executive_summary, incident_detail, threat_intelligence, user_activity, firewall_list_traffic)
- check_ip_reputation : vérifier la réputation, le score de menace multi-source (AbuseIPDB, VirusTotal, AlienVault, GreyNoise), la localisation géographique (pays, ville/town, région) et le fournisseur/ISP d'une adresse IP
- sync_threat_feed : synchroniser automatiquement le flux de menaces AbuseIPDB (IPs à haute confiance ≥95%)
- get_country_stats : obtenir les statistiques géographiques des IP blacklistées (top pays, distribution géographique)

COMPORTEMENT :
- RÉPONSE TOUJOURS dans la même langue que l'utilisateur (français ou anglais).
- Comprends le langage naturel en français et en anglais.
- Si une information manque (IP, ID alerte, période, format), pose UNE question claire avant d'agir.
- Quand l'utilisateur donne un ID d'alerte et demande une analyse ou si c'est une attaque : appelle analyze_alert, interprète le résultat, donne un verdict argumenté et propose des actions concrètes.
- Après chaque appel d'outil, synthétise le résultat pour l'analyste (2 à 5 phrases, ton professionnel SOC).
- Pour les purges globales : demande confirmation, puis rappelle l'outil avec confirmed=true.
- Pour les exports : vérifie type, format et période ; calcule les dates ISO si l'utilisateur dit « 7 derniers jours », « aujourd'hui », etc.
- RAPPORTS — SUIVI DE CONTEXTE : si un [Contexte rapport précédent] est fourni et l'utilisateur demande « le même », « en excel », « sur 3 semaines », etc., réutilise les paramètres non modifiés (type, format ou dates) et appelle generate_report immédiatement avec les nouvelles valeurs. Ne redemande pas ce qui est déjà connu.
- Ne invente jamais de données. Contexte : Suricata (alert=détecte, drop=bloque), Wazuh.
- Pas de formules creuses (« Bonjour », « Bien sûr »). Sois direct et utile.
`;
    } else {
      return `
You are the interactive SOC assistant for SentinelOps. You help analysts investigate, respond to, and document incidents.

AVAILABLE TOOLS (call them based on intent, not keywords):
- analyze_alert: analyze an alert by ID (real attack, false positive, severity, recommendations)
- get_daily_summary: daily operational statistics
- block_ip / unblock_ip: blacklist management
- add_to_whitelist / remove_from_whitelist: whitelist management
- purge_blacklist / purge_whitelist: clear a list (confirmed=true only after explicit confirmation)
- get_firewall_history: history of blacklist/whitelist operations (who blocked/unblocked, when, why). Can filter by list (blacklist/whitelist) and limit number of entries.
- generate_report: export a PDF/Excel report (types: executive_summary, incident_detail, threat_intelligence, user_activity, firewall_list_traffic)
- check_ip_reputation: check multi-source IP reputation, threat score (AbuseIPDB, VirusTotal, AlienVault, GreyNoise), geographic location (country, city/town, region), and ISP
- sync_threat_feed: automatically sync AbuseIPDB threat feed (high confidence IPs ≥95%)
- get_country_stats: get geographic statistics of blacklisted IPs (top countries, geographic distribution)

BEHAVIOR:
- ALWAYS respond in the same language as the user (French or English).
- Understand natural language in French and English.
- If information is missing (IP, alert ID, period, format), ask ONE clear question before acting.
- When the user provides an alert ID and requests analysis or if it's an attack: call analyze_alert, interpret the result, provide an argued verdict and suggest concrete actions.
- After each tool call, synthesize the result for the analyst (2-5 sentences, professional SOC tone).
- For global purges: request confirmation, then recall the tool with confirmed=true.
- For exports: verify type, format and period; calculate ISO dates if user says "last 7 days", "today", etc.
- REPORTS — CONTEXT TRACKING: if a [Previous report context] is provided and user asks for "the same", "in excel", "for 3 weeks", etc., reuse unchanged parameters (type, format or dates) and call generate_report immediately with new values. Don't ask for what's already known.
- Never invent data. Context: Suricata (alert=detects, drop=blocks), Wazuh.
- No empty formulas ("Hello", "Of course"). Be direct and useful.
`;
    }
  }

  private async fetchAlertContext(alertId: string): Promise<string> {
    try {
      let alert: any = null;

      try {
        const directAlerts = await this.wazuhService.fetchRecentAlerts({
          id: alertId,
          limit: 1,
        });
        if (directAlerts && directAlerts.length > 0) {
          alert = directAlerts[0];
        }
      } catch (directError) {
        console.warn(
          `[Assistant] Direct alert query failed for ID ${alertId}:`,
          (directError as Error).message,
        );
      }

      if (!alert) {
        const alerts = await this.wazuhService.fetchRecentAlerts({
          limit: 1000,
        });
        alert = alerts.find((a) => a.rule?.id === alertId || a.id === alertId);
      }

      if (!alert) {
        return `Aucun détail trouvé pour l'alerte ID ${alertId}.`;
      }

      return `
Alerte de sécurité (Suricata/Wazuh) :
- ID : ${alert.id || alertId}
- Signature : ${alert.rule?.description || 'N/A'}
- Sévérité : ${alert.rule?.level || 'N/A'}
- Catégorie : ${alert.rule?.groups?.join(', ') || 'N/A'}
- IP source : ${alert.data?.src_ip || 'N/A'}
- IP destination : ${alert.data?.dest_ip || 'N/A'}
- Port destination : ${alert.data?.dest_port || 'N/A'}
- Protocole : ${alert.data?.protocol || 'N/A'}
- Horodatage : ${alert.timestamp || 'N/A'}
- Agent : ${alert.agent?.name || 'N/A'}
`;
    } catch (e) {
      console.error(e);
      return `Impossible de récupérer l'alerte ${alertId}.`;
    }
  }

  private isValidIpv4(ip: string): boolean {
    const parts = ip.split('.').map((part) => Number(part));
    return (
      parts.length === 4 &&
      parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    );
  }

  private normalizeIps(raw: unknown): { ips: string[]; error?: string } {
    if (!Array.isArray(raw) || raw.length === 0) {
      return { ips: [], error: 'Aucune adresse IP fournie.' };
    }

    const ips = [
      ...new Set(raw.map(String).filter((ip) => this.isValidIpv4(ip))),
    ];
    if (ips.length === 0) {
      return {
        ips: [],
        error: 'Adresses IP invalides. Fournissez des IPv4 valides.',
      };
    }

    return { ips };
  }

  private async runStructuredAnalysis(context: string): Promise<{
    summary: string;
    investigationSteps: string[];
    remediationSteps: string[];
    isLikelyAttack: boolean;
    confidence: string;
  }> {
    const prompt = `
${context}

Analyse cette alerte et réponds STRICTEMENT en JSON (sans markdown) :
{
  "summary": "résumé en 2-3 phrases",
  "investigationSteps": ["étape 1", "étape 2", "étape 3"],
  "remediationSteps": ["action 1", "action 2"],
  "isLikelyAttack": true,
  "confidence": "high|medium|low"
}
`;

    try {
      const model = this.genAI.getGenerativeModel({ model: this.modelName });
      const result = await model.generateContent(prompt);
      let text = result.response.text().trim();

      if (text.startsWith('```json')) {
        text = text.substring(7, text.length - 3).trim();
      } else if (text.startsWith('```')) {
        text = text.substring(3, text.length - 3).trim();
      }

      return JSON.parse(text);
    } catch (error) {
      console.error('Error running structured analysis:', error);
      return {
        summary: 'Analyse indisponible pour cette alerte.',
        investigationSteps: [],
        remediationSteps: [],
        isLikelyAttack: false,
        confidence: 'low',
      };
    }
  }

  /** Tools that modify firewall state — viewers are not allowed to call these. */
  private static readonly MUTATING_TOOLS = new Set([
    'block_ip',
    'unblock_ip',
    'add_to_whitelist',
    'remove_from_whitelist',
    'purge_blacklist',
    'purge_whitelist',
  ]);

  private async executeToolCall(
    call: FunctionCall,
    ctx: ToolExecutionContext,
  ): Promise<{
    result: Record<string, unknown>;
    mutation?: AssistantMutation;
  }> {
    // Viewers may read / analyse but cannot mutate firewall lists
    if (
      ctx.userRole === UserRole.VIEWER &&
      AssistantService.MUTATING_TOOLS.has(call.name)
    ) {
      return {
        result: {
          success: false,
          error: 'Permission denied',
        },
      };
    }

    const args = (call.args || {}) as Record<string, unknown>;

    switch (call.name) {
      case 'analyze_alert': {
        const alertId = String(args.alertId || '').trim();
        if (!alertId) {
          return { result: { success: false, error: 'alertId requis.' } };
        }

        const context = await this.fetchAlertContext(alertId);
        if (
          context.startsWith('Aucun détail') ||
          context.startsWith('Impossible')
        ) {
          return { result: { success: false, alertId, error: context } };
        }

        const analysis = await this.runStructuredAnalysis(context);
        return {
          result: {
            success: true,
            alertId,
            context,
            analysis,
            verdict: analysis.isLikelyAttack
              ? `Probable attaque (confiance ${analysis.confidence})`
              : `Probable faux positif ou activité bénigne (confiance ${analysis.confidence})`,
          },
        };
      }

      case 'get_daily_summary': {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const stats = await this.wazuhService.getAlertStats({
          startDate: todayStart.toISOString(),
        });
        return {
          result: {
            success: true,
            date: todayStart.toISOString().slice(0, 10),
            totalAlerts: stats.totalAlerts,
            severityDistribution: stats.severityDistribution,
            attacksByType: stats.attacksByType,
            topSourceIps: stats.topSourceIps?.slice(0, 5) || [],
          },
        };
      }

      case 'block_ip': {
        const { ips, error } = this.normalizeIps(args.ips);
        if (error) return { result: { success: false, error } };

        const reason = String(
          args.reason || `Bloqué via assistant: ${ctx.userMessage}`,
        );
        const affectedIps: string[] = [];
        const alreadyBlockedIps: string[] = [];
        const inWhitelistIps: string[] = [];

        for (const ip of ips) {
          // Check if IP is already blacklisted
          if (await this.blacklistService.isBlacklisted(ip)) {
            alreadyBlockedIps.push(ip);
            continue;
          }

          // Check if IP is in whitelist
          if (await this.whitelistService.isWhitelisted(ip)) {
            inWhitelistIps.push(ip);
            continue;
          }

          await this.blacklistService.block(
            ip,
            reason,
            BlockSource.MANUAL,
            ctx.userId,
            ctx.username,
          );
          affectedIps.push(ip);
        }

        // If all IPs were already blocked or in whitelist, return appropriate message
        if (affectedIps.length === 0) {
          const messages: string[] = [];
          if (alreadyBlockedIps.length > 0) {
            messages.push(`déjà bloquées: ${alreadyBlockedIps.join(', ')}`);
          }
          if (inWhitelistIps.length > 0) {
            messages.push(`dans la whitelist: ${inWhitelistIps.join(', ')}`);
          }
          return {
            result: {
              success: false,
              message: `Les adresses IP suivantes sont ${messages.join(' et ')}`,
              alreadyBlocked: alreadyBlockedIps,
              inWhitelist: inWhitelistIps,
            },
          };
        }

        // If some IPs were already blocked or in whitelist, include warning
        const messages: string[] = [];
        if (alreadyBlockedIps.length > 0) {
          messages.push(`${alreadyBlockedIps.length} IP(s) déjà bloquée(s): ${alreadyBlockedIps.join(', ')}`);
        }
        if (inWhitelistIps.length > 0) {
          messages.push(`${inWhitelistIps.length} IP(s) dans la whitelist: ${inWhitelistIps.join(', ')}`);
        }
        const message = messages.length > 0
          ? `${affectedIps.length} IP(s) bloquée(s). ${messages.join('. ')}`
          : undefined;

        return {
          result: { 
            success: true, 
            action: 'block', 
            ips: affectedIps,
            ...(message && { message }),
          },
          mutation: { type: 'ip-list-changed', ips: affectedIps },
        };
      }

      case 'unblock_ip': {
        const { ips, error } = this.normalizeIps(args.ips);
        if (error) return { result: { success: false, error } };

        for (const ip of ips) {
          await this.blacklistService.unblock(ip, ctx.userId, ctx.username);
        }

        return {
          result: { success: true, action: 'unblock', ips },
          mutation: { type: 'ip-list-changed', ips },
        };
      }

      case 'add_to_whitelist': {
        const { ips, error } = this.normalizeIps(args.ips);
        if (error) return { result: { success: false, error } };

        const reason = String(
          args.reason || `Ajoutée via assistant: ${ctx.userMessage}`,
        );
        const affectedIps: string[] = [];
        const alreadyWhitelistedIps: string[] = [];
        const inBlacklistIps: string[] = [];

        for (const ip of ips) {
          // Check if IP is already whitelisted
          if (await this.whitelistService.isWhitelisted(ip)) {
            alreadyWhitelistedIps.push(ip);
            continue;
          }

          // Check if IP is in blacklist
          if (await this.blacklistService.isBlacklisted(ip)) {
            inBlacklistIps.push(ip);
            continue;
          }

          await this.whitelistService.add(ip, reason, ctx.userId, ctx.username);
          affectedIps.push(ip);
        }

        // If all IPs were already whitelisted or in blacklist, return appropriate message
        if (affectedIps.length === 0) {
          const messages: string[] = [];
          if (alreadyWhitelistedIps.length > 0) {
            messages.push(`déjà dans la whitelist: ${alreadyWhitelistedIps.join(', ')}`);
          }
          if (inBlacklistIps.length > 0) {
            messages.push(`dans la blacklist: ${inBlacklistIps.join(', ')}`);
          }
          return {
            result: {
              success: false,
              message: `Les adresses IP suivantes sont ${messages.join(' et ')}`,
              alreadyWhitelisted: alreadyWhitelistedIps,
              inBlacklist: inBlacklistIps,
            },
          };
        }

        // If some IPs were already whitelisted or in blacklist, include warning
        const messages: string[] = [];
        if (alreadyWhitelistedIps.length > 0) {
          messages.push(`${alreadyWhitelistedIps.length} IP(s) déjà dans la whitelist: ${alreadyWhitelistedIps.join(', ')}`);
        }
        if (inBlacklistIps.length > 0) {
          messages.push(`${inBlacklistIps.length} IP(s) dans la blacklist: ${inBlacklistIps.join(', ')}`);
        }
        const message = messages.length > 0
          ? `${affectedIps.length} IP(s) ajoutée(s) à la whitelist. ${messages.join('. ')}`
          : undefined;

        return {
          result: { 
            success: true, 
            action: 'whitelist-add', 
            ips: affectedIps,
            ...(message && { message }),
          },
          mutation: { type: 'ip-list-changed', ips: affectedIps },
        };
      }

      case 'remove_from_whitelist': {
        const { ips, error } = this.normalizeIps(args.ips);
        if (error) return { result: { success: false, error } };

        for (const ip of ips) {
          await this.whitelistService.remove(ip, ctx.userId, ctx.username);
        }

        return {
          result: { success: true, action: 'whitelist-remove', ips },
          mutation: { type: 'ip-list-changed', ips },
        };
      }

      case 'purge_blacklist': {
        if (args.confirmed !== true) {
          return {
            result: {
              success: false,
              needsConfirmation: true,
              message:
                "Demandez confirmation à l'utilisateur avant de purger toute la blacklist.",
            },
          };
        }

        const ips = await this.blacklistService.purgeAll(
          ctx.userId,
          ctx.username,
        );
        return {
          result: {
            success: true,
            action: 'purge-blacklist',
            count: ips.length,
            ips,
          },
          mutation: { type: 'ip-list-changed', ips },
        };
      }

      case 'purge_whitelist': {
        if (args.confirmed !== true) {
          return {
            result: {
              success: false,
              needsConfirmation: true,
              message:
                "Demandez confirmation à l'utilisateur avant de purger toute la whitelist.",
            },
          };
        }

        const ips = await this.whitelistService.purgeAll(
          ctx.userId,
          ctx.username,
        );
        return {
          result: {
            success: true,
            action: 'purge-whitelist',
            count: ips.length,
            ips,
          },
          mutation: { type: 'ip-list-changed', ips },
        };
      }

      case 'generate_report': {
        const format = String(args.format || '').toLowerCase();
        const reportType = String(args.reportType || '') as ReportType;
        const startDate = String(args.startDate || '');
        const endDate = String(args.endDate || '');

        if (!['pdf', 'excel'].includes(format)) {
          return {
            result: {
              success: false,
              error: 'Format invalide. Utilisez pdf ou excel.',
            },
          };
        }

        if (!Object.values(ReportType).includes(reportType)) {
          return {
            result: {
              success: false,
              error: `Type invalide. Valeurs : ${Object.values(ReportType).join(', ')}`,
            },
          };
        }

        if (
          !startDate ||
          !endDate ||
          Number.isNaN(Date.parse(startDate)) ||
          Number.isNaN(Date.parse(endDate))
        ) {
          return {
            result: {
              success: false,
              error: 'Dates startDate/endDate ISO 8601 requises.',
            },
          };
        }

        const reportParams: ReportParams = {
          format: format as 'pdf' | 'excel',
          reportType,
          startDate,
          endDate,
        };

        return {
          result: {
            success: true,
            action: 'generate-report',
            ...reportParams,
          },
          mutation: {
            type: 'report-request',
            report: reportParams,
          },
        };
      }

      case 'get_firewall_history': {
        const rawListType = args.listType
          ? String(args.listType).toLowerCase()
          : undefined;
        let listType: FirewallListType | undefined;

        if (rawListType === 'blacklist') listType = FirewallListType.BLACKLIST;
        else if (rawListType === 'whitelist')
          listType = FirewallListType.WHITELIST;

        const limit = args.limit ? Number(args.limit) : undefined;
        const entries = await this.firewallHistoryService.getHistory(
          listType,
          limit,
        );

        return {
          result: {
            success: true,
            count: entries.length,
            history: entries.map((e) => ({
              id: e.id,
              listType: e.listType,
              action: e.action,
              ip: e.ip,
              reason: e.reason,
              performedBy: e.performedBy,
              date: e.createdAt,
            })),
          },
        };
      }

      case 'check_ip_reputation': {
        const ip = String(args.ip || '').trim();
        if (!ip) {
          return { result: { success: false, error: 'IP requis.' } };
        }

        const threatInfo = await this.threatIntelService.checkIp(ip);
        if (threatInfo) {
          const score = threatInfo.compositeScore ?? threatInfo.abuseScore ?? 0;
          return {
            result: {
              success: true,
              ip,
              compositeScore: score,
              abuseScore: score,
              verdict:
                threatInfo.verdict ||
                (score >= 60
                  ? 'critical'
                  : score >= 25
                    ? 'suspicious'
                    : 'clean'),
              severity:
                score >= 60
                  ? 'high / critical'
                  : score >= 25
                    ? 'medium / suspicious'
                    : 'low / clean',
              countryCode: threatInfo.countryCode,
              countryName: threatInfo.countryName,
              city: threatInfo.city,
              region: threatInfo.region,
              isp: threatInfo.isp,
              totalReports: threatInfo.totalReports,
              categories: threatInfo.categories,
              activeSources: threatInfo.activeSources || 1,
              sourcesBreakdown: threatInfo.sources,
            },
          };
        } else {
          return {
            result: {
              success: true,
              ip,
              message: 'Aucune donnée de réputation disponible pour cette IP.',
            },
          };
        }
      }

      case 'sync_threat_feed': {
        const syncResult = await this.threatFeedScheduler.performSync();
        return {
          result: {
            success: true,
            added: syncResult.added,
            skipped: syncResult.skipped,
            total: syncResult.total,
            message: `Synchronisation terminée : ${syncResult.added} ajoutées, ${syncResult.skipped} ignorées, ${syncResult.total} traitées.`,
          },
        };
      }

      case 'get_country_stats': {
        const countryStats = await this.blacklistService.getCountryStats();
        return {
          result: {
            success: true,
            countries: countryStats.map((stat) => ({
              country: stat.countryCode,
              count: stat.count,
            })),
            total: countryStats.length,
            message: `${countryStats.length} pays représentés dans la blacklist.`,
          },
        };
      }

      default:
        return {
          result: { success: false, error: `Outil inconnu: ${call.name}` },
        };
    }
  }

  private parseLogMetadata(
    metadata: string | null,
  ): { lastReport?: ReportParams } | null {
    if (!metadata) return null;
    try {
      return JSON.parse(metadata);
    } catch {
      return null;
    }
  }

  private resolveLastReport(
    history: ConversationLog[],
    dtoLastReport?: ReportParams,
  ): ReportParams | null {
    for (let i = history.length - 1; i >= 0; i--) {
      const parsed = this.parseLogMetadata(history[i].metadata);
      if (parsed?.lastReport) return parsed.lastReport;
    }
    return dtoLastReport || null;
  }

  private formatReportContext(report: ReportParams): string {
    return `[Contexte rapport précédent : type=${report.reportType}, format=${report.format}, startDate=${report.startDate}, endDate=${report.endDate}]`;
  }

  private buildContents(
    history: ConversationLog[],
    userMessage: string,
    alertId?: string,
    lastReport?: ReportParams | null,
  ): Content[] {
    const contents: Content[] = [];

    for (const log of history) {
      contents.push({ role: 'user', parts: [{ text: log.userMessage }] });
      contents.push({ role: 'model', parts: [{ text: log.aiReply }] });
    }

    const contextLines: string[] = [];
    if (alertId) {
      contextLines.push(`[Contexte : alerte courante ID ${alertId}]`);
    }
    if (lastReport) {
      contextLines.push(this.formatReportContext(lastReport));
    }

    const message =
      contextLines.length > 0
        ? `${contextLines.join('\n')}\n${userMessage}`
        : userMessage;

    contents.push({ role: 'user', parts: [{ text: message }] });
    return contents;
  }

  private mergeMutations(
    mutations: AssistantMutation[],
  ): AssistantMutation | undefined {
    if (mutations.length === 0) return undefined;

    const ipMutations = mutations.filter((m) => m.type === 'ip-list-changed');
    const reportMutation = mutations.find((m) => m.type === 'report-request');

    if (reportMutation) return reportMutation;

    if (ipMutations.length > 0) {
      const ips = [...new Set(ipMutations.flatMap((m) => m.ips || []))];
      return { type: 'ip-list-changed', ips };
    }

    return undefined;
  }

  private async runChatWithTools(
    contents: Content[],
    ctx: ToolExecutionContext,
  ): Promise<{ reply: string; mutation?: AssistantMutation }> {
    const isFrench = ctx.language === 'fr';
    const model = this.genAI.getGenerativeModel({
      model: this.modelName,
      systemInstruction: this.getSystemPrompt(ctx.language || 'fr'),
      tools: [{ functionDeclarations: ASSISTANT_FUNCTION_DECLARATIONS }],
      toolConfig: {
        functionCallingConfig: { mode: FunctionCallingMode.AUTO },
      },
    });

    const mutations: AssistantMutation[] = [];
    const currentContents = [...contents];
    const maxRounds = 6;

    for (let round = 0; round < maxRounds; round++) {
      const result = await model.generateContent({ contents: currentContents });
      const response = result.response;
      const functionCalls = response.functionCalls();

      if (!functionCalls || functionCalls.length === 0) {
        return {
          reply:
            response.text() ||
            (isFrench
              ? "Je n'ai pas pu formuler de réponse."
              : 'I could not formulate a response.'),
          mutation: this.mergeMutations(mutations),
        };
      }

      const modelParts = response.candidates?.[0]?.content?.parts;
      if (modelParts?.length) {
        currentContents.push({ role: 'model', parts: modelParts });
      } else {
        currentContents.push({
          role: 'model',
          parts: functionCalls.map((fc) => ({ functionCall: fc })),
        });
      }

      const functionResponseParts: FunctionResponsePart[] = [];
      for (const call of functionCalls) {
        const { result: toolResult, mutation } = await this.executeToolCall(
          call,
          ctx,
        );
        if (mutation) mutations.push(mutation);
        functionResponseParts.push({
          functionResponse: {
            name: call.name,
            response: toolResult,
          },
        });
      }

      currentContents.push({ role: 'function', parts: functionResponseParts });
    }

    return {
      reply:
        "Je n'ai pas pu finaliser la réponse. Pouvez-vous reformuler votre demande ?",
      mutation: this.mergeMutations(mutations),
    };
  }

  async chat(
    userId: number,
    username: string,
    userRole: string,
    dto: ChatRequestDto,
  ) {
    const conversationId = dto.conversationId || randomUUID();
    const history = dto.conversationId
      ? await this.conversationLogRepo.find({
          where: { conversationId: dto.conversationId },
          order: { createdAt: 'ASC' },
        })
      : [];

    const lastReport = this.resolveLastReport(history, dto.lastReport);
    const contents = this.buildContents(
      history,
      dto.message,
      dto.alertId,
      lastReport,
    );
    const ctx: ToolExecutionContext = {
      userId,
      username,
      userMessage: dto.message,
      userRole: userRole,
      language: (dto as any).language || 'fr',
    };

    try {
      const { reply, mutation } = await this.runChatWithTools(contents, ctx);

      const log = this.conversationLogRepo.create({
        userId,
        alertId: dto.alertId,
        userMessage: dto.message,
        aiReply: reply,
        conversationId,
        metadata:
          mutation?.type === 'report-request' && mutation.report
            ? JSON.stringify({ lastReport: mutation.report })
            : null,
      });
      await this.conversationLogRepo.save(log);

      return {
        reply,
        conversationId,
        ...(mutation ? { mutation } : {}),
      };
    } catch (error: any) {
      console.error('Error calling Gemini API:', error);

      // Check for quota exceeded error (429)
      if (
        error?.status === 429 ||
        error?.message?.includes('429') ||
        error?.message?.includes('quota')
      ) {
        throw new InternalServerErrorException(
          'Free trial quota exceeded. Please upgrade your Gemini API plan or wait for the daily quota reset.',
        );
      }

      throw new InternalServerErrorException(
        'Erreur lors de la communication avec le service IA',
      );
    }
  }

  async getHistory(conversationId: string) {
    return this.conversationLogRepo.find({
      where: { conversationId },
      order: { createdAt: 'ASC' },
    });
  }

  async getQuickAnalysis(_userId: number, alertId: string) {
    const context = await this.fetchAlertContext(alertId);
    const analysis = await this.runStructuredAnalysis(context);
    return {
      summary: analysis.summary,
      investigationSteps: analysis.investigationSteps,
      remediationSteps: analysis.remediationSteps,
    };
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
      return await this.wazuhService.getAlertStats({
        startDate: todayStart.toISOString(),
      });
    } catch (error) {
      console.error('Error fetching daily summary:', error);
      return {
        totalAlerts: 0,
        severityDistribution: {},
        attacksByType: {},
        topSourceIps: [],
        alertsOverTime: [],
      };
    }
  }
}
