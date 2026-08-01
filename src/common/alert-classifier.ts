/**
 * Classify a Wazuh/Suricata alert into a readable attack/event type.
 * Prefer specific categories; fall back to the rule description so we never
 * dump everything into a vague "Autre" bucket.
 */

const GENERIC_GROUPS = new Set([
  'syslog',
  'firewall',
  'ids',
  'gdpr',
  'pci_dss',
  'hipaa',
  'nist_800_53',
  'tsc',
  'gpg13',
  'ossec',
  'linux',
  'windows',
  'mac',
  'debian',
  'ubuntu',
  'centos',
  'rhel',
]);

type RuleMatcher = {
  label: string;
  test: (desc: string, groups: string[], tactics: string[]) => boolean;
};

const MATCHERS: RuleMatcher[] = [
  {
    label: 'SQL Injection',
    test: (d) => /sql\s*injection|sqli|union\s+select/i.test(d),
  },
  {
    label: 'XSS / Injection Web',
    test: (d) => /cross.?site|xss|script\s*injection/i.test(d),
  },
  {
    label: 'Port Scanning',
    test: (d, g) =>
      /port\s*scan|nmap|masscan|reconnaissance/i.test(d) ||
      g.includes('recon'),
  },
  {
    label: 'SSH Brute Force',
    test: (d, g) =>
      (/ssh/i.test(d) && /brut|fail|invalid|authentication/i.test(d)) ||
      (g.includes('authentication_failed') && /ssh/i.test(d)),
  },
  {
    label: 'Échec d\'authentification',
    test: (d, g) =>
      g.includes('authentication_failed') ||
      /authentication\s*fail|login\s*fail|invalid\s*user|failed\s*password/i.test(d),
  },
  {
    label: 'Élévation de privilèges',
    test: (d, g, t) =>
      /sudoers|privilege\s*escalat|sudo:\s|became\s*root/i.test(d) ||
      g.includes('pam_sudo') ||
      t.includes('privilege escalation'),
  },
  {
    label: 'Accès root / sudo',
    test: (d) => /\bsudo\b|successful su |to root|dstuser.*root/i.test(d),
  },
  {
    label: 'Exploit (Shellshock)',
    test: (d) => /shellshock|cve-2014-6271/i.test(d),
  },
  {
    label: 'Malware / Trojan',
    test: (d, g) =>
      g.includes('malware') ||
      /malware|trojan|ransomware|backdoor|virus|worm/i.test(d),
  },
  {
    label: 'Vulnérabilité',
    test: (d, g) =>
      g.includes('vulnerability') || /cve-\d{4}-\d+|vulnerabilit/i.test(d),
  },
  {
    label: 'Intégrité des fichiers (FIM)',
    test: (d, g) =>
      g.includes('syscheck') ||
      g.includes('fim') ||
      /file\s*integrity|syscheck|integrity\s*checksum/i.test(d),
  },
  {
    label: 'Suricata / IDS',
    test: (d, g) =>
      g.includes('suricata') ||
      g.includes('ids') ||
      /suricata|et\s*pro|emerging.?threat/i.test(d),
  },
  {
    label: 'Web Attack',
    test: (d, g) =>
      g.includes('web') ||
      g.includes('apache') ||
      g.includes('nginx') ||
      /http\s*attack|web\s*attack|directory\s*traversal|\.\.\//i.test(d),
  },
  {
    label: 'AppArmor',
    test: (d, g) => g.includes('apparmor') || /apparmor/i.test(d),
  },
  {
    label: 'Firewall / Drop',
    test: (d, g) =>
      g.includes('firewall') ||
      /firewall|iptables|nftables|packet\s*drop|blocked/i.test(d),
  },
  {
    label: 'Persistance',
    test: (_d, _g, t) => t.includes('persistence'),
  },
  {
    label: 'Defense Evasion',
    test: (_d, _g, t) => t.includes('defense evasion'),
  },
  {
    label: 'Initial Access',
    test: (_d, _g, t) => t.includes('initial access'),
  },
  {
    label: 'Exfiltration',
    test: (d, _g, t) => t.includes('exfiltration') || /exfiltrat/i.test(d),
  },
  {
    label: 'Command & Control',
    test: (d, _g, t) =>
      t.includes('command and control') || /c2|command.?and.?control|beacon/i.test(d),
  },
  {
    label: 'Lateral Movement',
    test: (_d, _g, t) => t.includes('lateral movement'),
  },
  {
    label: 'Session PAM / Login',
    test: (d, g) =>
      g.includes('pam') ||
      /pam:|session opened|session closed|user login|logged in/i.test(d),
  },
  {
    label: 'Audit / System',
    test: (d, g) =>
      g.includes('audit') ||
      g.includes('systemd') ||
      /auditd|netstat|listened ports/i.test(d),
  },
];

function truncateLabel(text: string, max = 55): string {
  const cleaned = text.replace(/\s+/g, ' ').trim();
  if (cleaned.length <= max) return cleaned;
  return cleaned.slice(0, max - 1).trimEnd() + '…';
}

export function classifyAlertCategory(alert: any): string {
  const desc = (alert?.rule?.description || '').trim();
  const descLower = desc.toLowerCase();
  const groups = (alert?.rule?.groups || []).map((g: string) =>
    String(g).toLowerCase(),
  );

  const rawTactics =
    alert?.rule?.mitre?.tactic ||
    alert?.rule?.mitre?.tactics ||
    alert?.rule?.tactic ||
    [];
  const tactics = (Array.isArray(rawTactics) ? rawTactics : [rawTactics])
    .filter(Boolean)
    .map((t: string) => String(t).toLowerCase());

  for (const matcher of MATCHERS) {
    if (matcher.test(descLower, groups, tactics)) {
      return matcher.label;
    }
  }

  // Prefer first MITRE tactic if present
  if (tactics.length > 0) {
    const tactic = rawTactics[0];
    return typeof tactic === 'string' ? tactic : String(tactic);
  }

  // Prefer a specific Wazuh group over generic buckets
  const specificGroup = groups.find((g) => !GENERIC_GROUPS.has(g));
  if (specificGroup) {
    return specificGroup
      .split(/[_-]/)
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  }

  // Last resort: real rule description (never "Autre")
  if (desc) return truncateLabel(desc);

  return 'Événement non classifié';
}

/** Sort categories by count desc; keep top N and bucket the rest. */
export function consolidateCategories(
  counts: Record<string, number>,
  topN = 12,
): Record<string, number> {
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (sorted.length <= topN) {
    return Object.fromEntries(sorted);
  }

  const top = sorted.slice(0, topN - 1);
  const rest = sorted.slice(topN - 1);
  const restCount = rest.reduce((sum, [, n]) => sum + n, 0);
  const restTypes = rest.length;

  return {
    ...Object.fromEntries(top),
    [`Autres (${restTypes} types)`]: restCount,
  };
}
