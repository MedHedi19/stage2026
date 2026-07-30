/**
 * Suricata SIDs that trigger automatic IP blocking
 * These are port scan and reconnaissance rules - NOT SQLi/SSH bruteforce
 * SQLi and SSH bruteforce stay alert-only for manual review
 */
export const AUTO_BLOCK_SIDS = [
  1000001, // Port scan (TCP)
  1000002, // Port scan (UDP)
  1000003, // Port scan (SYN)
  1000004, // Port scan (FIN)
  1000009, // Nmap scan
  1000010, // Known scanner user-agent
  1000011, // Additional scan detection
  1000013, // Additional scan detection
  1000014, // Additional scan detection
];
