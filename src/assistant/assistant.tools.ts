import { FunctionDeclaration, SchemaType } from '@google/generative-ai';
import { ReportType } from '../reports/report-types.enum';

export interface ReportParams {
  format: 'pdf' | 'excel';
  reportType: ReportType;
  startDate: string;
  endDate: string;
}

export interface AssistantMutation {
  type: 'ip-list-changed' | 'report-request';
  ips?: string[];
  report?: ReportParams;
}

export interface ToolExecutionContext {
  userId: number;
  username: string;
  userMessage: string;
  userRole: string;
  language?: string;
}

const REPORT_TYPE_VALUES = Object.values(ReportType);

export const ASSISTANT_FUNCTION_DECLARATIONS: FunctionDeclaration[] = [
  {
    name: 'analyze_alert',
    description:
      'Récupère et analyse une alerte de sécurité par son ID (Wazuh/Suricata). ' +
      "Utilise cet outil quand l'utilisateur demande d'analyser une alerte, de dire si c'est une attaque, " +
      "un faux positif, ou d'évaluer la gravité d'un incident.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        alertId: {
          type: SchemaType.STRING,
          description:
            "Identifiant de l'alerte (rule.id, document _id ou ID numérique Wazuh).",
        },
      },
      required: ['alertId'],
    },
  },
  {
    name: 'get_daily_summary',
    description:
      'Récupère les statistiques des alertes du jour (volume, répartition par sévérité, top IPs). ' +
      'Utilise cet outil pour un résumé opérationnel de la journée.',
    parameters: {
      type: SchemaType.OBJECT,
      properties: {},
    },
  },
  {
    name: 'block_ip',
    description:
      'Bloque une ou plusieurs adresses IP en les ajoutant à la blacklist (Suricata drop). ' +
      "Retire automatiquement l'IP de la whitelist si elle y figure.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        ips: {
          type: SchemaType.ARRAY,
          description: "Liste d'adresses IPv4 à bloquer.",
          items: { type: SchemaType.STRING },
        },
        reason: {
          type: SchemaType.STRING,
          description: 'Motif du blocage (optionnel).',
        },
      },
      required: ['ips'],
    },
  },
  {
    name: 'unblock_ip',
    description: 'Retire une ou plusieurs adresses IP de la blacklist.',
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        ips: {
          type: SchemaType.ARRAY,
          description: "Liste d'adresses IPv4 à débloquer.",
          items: { type: SchemaType.STRING },
        },
      },
      required: ['ips'],
    },
  },
  {
    name: 'add_to_whitelist',
    description:
      'Ajoute une ou plusieurs adresses IP à la whitelist (trafic autorisé). ' +
      "Retire automatiquement l'IP de la blacklist si nécessaire.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        ips: {
          type: SchemaType.ARRAY,
          description: "Liste d'adresses IPv4 à autoriser.",
          items: { type: SchemaType.STRING },
        },
        reason: {
          type: SchemaType.STRING,
          description: "Motif de l'ajout (optionnel).",
        },
      },
      required: ['ips'],
    },
  },
  {
    name: 'remove_from_whitelist',
    description: 'Retire une ou plusieurs adresses IP de la whitelist.',
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        ips: {
          type: SchemaType.ARRAY,
          description: "Liste d'adresses IPv4 à retirer.",
          items: { type: SchemaType.STRING },
        },
      },
      required: ['ips'],
    },
  },
  {
    name: 'purge_blacklist',
    description:
      "Vide entièrement la blacklist. Action destructive : confirmed doit être true après confirmation explicite de l'utilisateur.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        confirmed: {
          type: SchemaType.BOOLEAN,
          description:
            'true uniquement après confirmation explicite (oui, confirmer, etc.).',
        },
      },
      required: ['confirmed'],
    },
  },
  {
    name: 'purge_whitelist',
    description:
      "Vide entièrement la whitelist. Action destructive : confirmed doit être true après confirmation explicite de l'utilisateur.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        confirmed: {
          type: SchemaType.BOOLEAN,
          description:
            'true uniquement après confirmation explicite (oui, confirmer, etc.).',
        },
      },
      required: ['confirmed'],
    },
  },
  {
    name: 'generate_report',
    description:
      'Exporte un rapport de sécurité (PDF ou Excel). ' +
      'Utilise cet outil pour toute demande de rapport, y compris les variantes du même rapport ' +
      '(ex. « le même en excel », « même type sur 3 semaines »). ' +
      "Si un contexte rapport précédent est disponible, réutilise les paramètres inchangés et modifie seulement ce que l'utilisateur demande.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        format: {
          type: SchemaType.STRING,
          description: 'Format du rapport : pdf ou excel.',
        },
        reportType: {
          type: SchemaType.STRING,
          description: `Type de rapport. Valeurs : ${REPORT_TYPE_VALUES.join(', ')}.`,
        },
        startDate: {
          type: SchemaType.STRING,
          description: 'Date de début ISO 8601 (ex. 2026-08-05T00:00:00.000Z).',
        },
        endDate: {
          type: SchemaType.STRING,
          description: 'Date de fin ISO 8601 (ex. 2026-08-12T23:59:59.999Z).',
        },
      },
      required: ['format', 'reportType', 'startDate', 'endDate'],
    },
  },
  {
    name: 'get_firewall_history',
    description:
      "Récupère l'historique des opérations (ajout, suppression, purge) sur la blacklist et/ou la whitelist. " +
      "Affiche qui a effectué chaque action (utilisateur ou système), l'IP concernée, la raison et la date. " +
      "Utilise cet outil quand l'utilisateur demande l'historique, les dernières actions, ou qui a bloqué/débloqué une IP.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        listType: {
          type: SchemaType.STRING,
          description:
            "Filtrer par type de liste : blacklist, whitelist. Omettre pour tout l'historique.",
        },
        limit: {
          type: SchemaType.NUMBER,
          description:
            "Nombre maximum d'entrées à retourner. Omettre pour tout l'historique.",
        },
      },
    },
  },
  {
    name: 'check_ip_reputation',
    description:
      "Vérifie la réputation, la localisation géographique (pays, ville/town, région) et le fournisseur/ISP d'une adresse IP " +
      'via les moteurs de Threat Intelligence (AbuseIPDB, VirusTotal, AlienVault OTX, GreyNoise). ' +
      "Retourne le score de menace global (0-100), le verdict (sain, suspect, malveillant), le pays, la ville, l'ISP, " +
      'le nombre de détections et le détail par source. ' +
      "Utilise cet outil quand l'utilisateur demande des informations sur une IP : d'où elle vient (quel pays, quelle ville/town), son score de réputation, sa dangerosité ou son historique d'attaques.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {
        ip: {
          type: SchemaType.STRING,
          description: 'Adresse IP à vérifier (IPv4).',
        },
      },
      required: ['ip'],
    },
  },
  {
    name: 'sync_threat_feed',
    description:
      'Déclenche manuellement la synchronisation du flux de menaces AbuseIPDB. ' +
      'Récupère les IP malveillantes à haute confiance (≥95%) et les ajoute à la blacklist. ' +
      "Retourne le nombre d'IP ajoutées, ignorées et le total traité. " +
      "Utilise cet outil quand l'utilisateur demande de synchroniser les menaces, mettre à jour la blacklist automatiquement, ou déclencher le flux de menaces.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {},
    },
  },
  {
    name: 'get_country_stats',
    description:
      'Récupère les statistiques géographiques des IP blacklistées. ' +
      'Retourne les pays les plus représentés dans la blacklist avec leurs comptes. ' +
      "Utilise cet outil quand l'utilisateur demande quels sont les pays les plus dangereux, les top pays, ou la distribution géographique des menaces.",
    parameters: {
      type: SchemaType.OBJECT,
      properties: {},
    },
  },
];
