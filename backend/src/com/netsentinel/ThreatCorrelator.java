package com.netsentinel;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * NetSentinel Threat Correlation & Incident Escalation Engine
 */
public class ThreatCorrelator {
    private final List<SecurityAlert> alertHistory = new CopyOnWriteArrayList<>();
    private final QuarantineManager quarantineManager;
    private final NetworkStats networkStats;
    private final int maxAlertCapacity = 1000;

    public ThreatCorrelator(QuarantineManager quarantineManager, NetworkStats networkStats) {
        this.quarantineManager = quarantineManager;
        this.networkStats = networkStats;
    }

    public synchronized void processIncomingAlert(SecurityAlert alert) {
        if (alert == null) return;

        // Auto-quarantine trigger for critical exploits or repeated high-severity attacks
        if ("CRITICAL".equalsIgnoreCase(alert.getSeverity())) {
            quarantineManager.blockIp(alert.getSourceIp(), "Auto-Mitigation: " + alert.getAttackType(), "CRITICAL");
            alert.setActionTaken("AUTO_QUARANTINED");
        } else if (quarantineManager.isBlocked(alert.getSourceIp())) {
            alert.setActionTaken("DROPPED_BLOCKED_IP");
        }

        // Record statistics
        networkStats.recordAlert(alert);

        // Store in bounded buffer (newest first)
        alertHistory.add(0, alert);
        if (alertHistory.size() > maxAlertCapacity) {
            alertHistory.remove(alertHistory.size() - 1);
        }
    }

    public List<SecurityAlert> getAlerts(int limit, String severityFilter) {
        List<SecurityAlert> filtered = new ArrayList<>();
        for (SecurityAlert alert : alertHistory) {
            if (severityFilter != null && !severityFilter.isEmpty() && !severityFilter.equalsIgnoreCase("ALL")) {
                if (!alert.getSeverity().equalsIgnoreCase(severityFilter)) {
                    continue;
                }
            }
            filtered.add(alert);
            if (filtered.size() >= limit) {
                break;
            }
        }
        return filtered;
    }

    public void clearAlerts() {
        alertHistory.clear();
    }

    public String generateCsvReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("Alert_ID,Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Protocol,Attack_Type,Severity,Action_Taken,Recommendation\n");
        for (SecurityAlert a : alertHistory) {
            sb.append("\"").append(a.getId()).append("\",");
            sb.append("\"").append(a.getTimestamp()).append("\",");
            sb.append("\"").append(a.getSourceIp()).append("\",");
            sb.append(a.getSourcePort()).append(",");
            sb.append("\"").append(a.getDestIp()).append("\",");
            sb.append(a.getDestPort()).append(",");
            sb.append("\"").append(a.getProtocol()).append("\",");
            sb.append("\"").append(a.getAttackType()).append("\",");
            sb.append("\"").append(a.getSeverity()).append("\",");
            sb.append("\"").append(a.getActionTaken()).append("\",");
            sb.append("\"").append(a.getRecommendation() != null ? a.getRecommendation().replace("\"", "\"\"") : "").append("\"\n");
        }
        return sb.toString();
    }

    public String alertsToJson(List<SecurityAlert> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < list.size(); i++) {
            sb.append(list.get(i).toJson());
            if (i < list.size() - 1) sb.append(",");
        }
        sb.append("]");
        return sb.toString();
    }
}
