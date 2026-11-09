package com.netsentinel;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * NetSentinel Quarantine & Windows Firewall Active Defense Manager (IPS)
 * Maintains real-time IP blacklists and synchronizes native Windows Defender Firewall rules.
 */
public class QuarantineManager {

    public static class QuarantineRecord {
        private final String ip;
        private final String reason;
        private final String timestamp;
        private final String severity;
        private final boolean firewallEnforced;

        public QuarantineRecord(String ip, String reason, String severity, boolean firewallEnforced) {
            this.ip = ip;
            this.reason = reason;
            this.severity = severity;
            this.firewallEnforced = firewallEnforced;
            this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }

        public String getIp() { return ip; }
        public String getReason() { return reason; }
        public String getTimestamp() { return timestamp; }
        public String getSeverity() { return severity; }
        public boolean isFirewallEnforced() { return firewallEnforced; }

        public String toJson() {
            return String.format(
                "{\"ip\":\"%s\",\"reason\":\"%s\",\"timestamp\":\"%s\",\"severity\":\"%s\",\"firewall_enforced\":%b}",
                ip, escape(reason), timestamp, severity, firewallEnforced
            );
        }

        private String escape(String s) {
            return s == null ? "" : s.replace("\"", "\\\"");
        }
    }

    private final Map<String, QuarantineRecord> blockedIps = new ConcurrentHashMap<>();

    public QuarantineManager() {
        // Pre-seed an initial quarantined threat
        blockIp("198.51.100.14", "Preemptive Blacklist: Known Mirai Botnet Node", "HIGH");
    }

    public boolean blockIp(String ip, String reason, String severity) {
        if (ip == null || ip.trim().isEmpty()) return false;
        String cleanIp = ip.trim();

        // Apply native Windows Firewall Inbound Block rule
        boolean applied = applyWindowsFirewallBlock(cleanIp, reason);

        blockedIps.put(cleanIp, new QuarantineRecord(cleanIp, reason, severity != null ? severity : "HIGH", applied));
        return true;
    }

    public boolean unblockIp(String ip) {
        if (ip == null) return false;
        String cleanIp = ip.trim();

        // Remove from native Windows Firewall
        removeWindowsFirewallBlock(cleanIp);

        return blockedIps.remove(cleanIp) != null;
    }

    public boolean isBlocked(String ip) {
        if (ip == null) return false;
        return blockedIps.containsKey(ip.trim());
    }

    public List<QuarantineRecord> getAllQuarantined() {
        return new ArrayList<>(blockedIps.values());
    }

    public int getBlockedCount() {
        return blockedIps.size();
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        List<QuarantineRecord> records = getAllQuarantined();
        for (int i = 0; i < records.size(); i++) {
            sb.append(records.get(i).toJson());
            if (i < records.size() - 1) sb.append(",");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Executes netsh advfirewall to add a native Windows Firewall Block rule.
     */
    private boolean applyWindowsFirewallBlock(String ip, String reason) {
        try {
            String ruleName = "NetSentinel-Block-" + ip;
            ProcessBuilder pb = new ProcessBuilder(
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + ruleName,
                "dir=in",
                "action=block",
                "remoteip=" + ip,
                "description=NetSentinel IPS: " + reason
            );
            Process p = pb.start();
            int code = p.waitFor();
            return code == 0;
        } catch (Exception e) {
            // Non-elevated environments will queue the rule in user-space
            return false;
        }
    }

    /**
     * Removes the rule from native Windows Firewall.
     */
    private void removeWindowsFirewallBlock(String ip) {
        try {
            String ruleName = "NetSentinel-Block-" + ip;
            ProcessBuilder pb = new ProcessBuilder(
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + ruleName
            );
            Process p = pb.start();
            p.waitFor();
        } catch (Exception ignored) {}
    }
}
