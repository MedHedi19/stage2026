export enum ReportType {
  EXECUTIVE_SUMMARY = 'executive_summary',
  INCIDENT_DETAIL = 'incident_detail',
  THREAT_INTELLIGENCE = 'threat_intelligence',
  USER_ACTIVITY = 'user_activity',
  FIREWALL_LIST_TRAFFIC = 'firewall_list_traffic',
}

export const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  [ReportType.EXECUTIVE_SUMMARY]: 'Executive Summary',
  [ReportType.INCIDENT_DETAIL]: 'Incident Detail',
  [ReportType.THREAT_INTELLIGENCE]: 'Threat Intelligence',
  [ReportType.USER_ACTIVITY]: 'User Activity',
  [ReportType.FIREWALL_LIST_TRAFFIC]: 'Firewall List Traffic',
};

export const REPORT_TYPE_DESCRIPTIONS: Record<ReportType, string> = {
  [ReportType.EXECUTIVE_SUMMARY]:
    'High-level overview for management with key metrics and trends',
  [ReportType.INCIDENT_DETAIL]:
    'Full incident lifecycle data with MITRE ATT&CK mapping',
  [ReportType.THREAT_INTELLIGENCE]:
    'IOCs detected, geolocation data, and threat actor information',
  [ReportType.USER_ACTIVITY]: 'User actions, login history, and audit trail',
  [ReportType.FIREWALL_LIST_TRAFFIC]:
    'Blacklist and whitelist entries with observed event volume and traffic per IP',
};
