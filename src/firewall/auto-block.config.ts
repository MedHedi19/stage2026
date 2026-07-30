/**
 * Suricata SIDs that trigger automatic IP blocking
 * These are port scan and reconnaissance rules - NOT SQLi/SSH bruteforce
 * SQLi and SSH bruteforce stay alert-only for manual review
 */
export const AUTO_BLOCK_SIDS = [
  1000001, // Port scan
  1000002, // Stealth scan
  1000003, // NULL scan
  1000004, // FIN scan
  1000009, // XMAS scan
  1000010, // Known scanner user-agent
];
