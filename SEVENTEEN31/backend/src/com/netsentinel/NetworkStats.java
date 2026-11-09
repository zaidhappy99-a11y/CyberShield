package com.netsentinel;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * NetSentinel Thread-safe Network Telemetry & Statistics Collector
 */
public class NetworkStats {
    private final AtomicLong totalAlerts = new AtomicLong(0);
    private final AtomicLong processedPackets = new AtomicLong(0);

    private final Map<String, AtomicLong> severityCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> attackerIpCounts = new ConcurrentHashMap<>();
    private final Map<Integer, AtomicLong> targetPortCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> protocolCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> attackTypeCounts = new ConcurrentHashMap<>();

    public NetworkStats() {
        severityCounts.put("LOW", new AtomicLong(0));
        severityCounts.put("MEDIUM", new AtomicLong(0));
        severityCounts.put("HIGH", new AtomicLong(0));
        severityCounts.put("CRITICAL", new AtomicLong(0));

        protocolCounts.put("TCP", new AtomicLong(0));
        protocolCounts.put("UDP", new AtomicLong(0));
        protocolCounts.put("HTTP", new AtomicLong(0));
        protocolCounts.put("DNS", new AtomicLong(0));
        protocolCounts.put("SSH", new AtomicLong(0));
        protocolCounts.put("ICMP", new AtomicLong(0));
    }

    public void recordAlert(SecurityAlert alert) {
        totalAlerts.incrementAndGet();

        // Severity count
        String s = alert.getSeverity() != null ? alert.getSeverity().toUpperCase() : "LOW";
        severityCounts.computeIfAbsent(s, k -> new AtomicLong(0)).incrementAndGet();

        // Source IP
        if (alert.getSourceIp() != null && !alert.getSourceIp().isEmpty()) {
            attackerIpCounts.computeIfAbsent(alert.getSourceIp(), k -> new AtomicLong(0)).incrementAndGet();
        }

        // Target Port
        if (alert.getDestPort() > 0) {
            targetPortCounts.computeIfAbsent(alert.getDestPort(), k -> new AtomicLong(0)).incrementAndGet();
        }

        // Protocol
        String proto = alert.getProtocol() != null ? alert.getProtocol().toUpperCase() : "TCP";
        protocolCounts.computeIfAbsent(proto, k -> new AtomicLong(0)).incrementAndGet();

        // Attack Type
        String attack = alert.getAttackType() != null ? alert.getAttackType() : "Unknown";
        attackTypeCounts.computeIfAbsent(attack, k -> new AtomicLong(0)).incrementAndGet();
    }

    public void incrementPacketCount(long count) {
        processedPackets.addAndGet(count);
    }

    public int calculateThreatScore() {
        long crit = severityCounts.getOrDefault("CRITICAL", new AtomicLong(0)).get();
        long high = severityCounts.getOrDefault("HIGH", new AtomicLong(0)).get();
        long med = severityCounts.getOrDefault("MEDIUM", new AtomicLong(0)).get();
        long low = severityCounts.getOrDefault("LOW", new AtomicLong(0)).get();

        long weighted = (crit * 30) + (high * 15) + (med * 5) + (low * 1);
        int score = (int) Math.min(100, Math.max(5, weighted));
        return score;
    }

    public String getThreatLevel(int score) {
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "ELEVATED";
        return "NORMAL";
    }

    public Map<String, Long> getTopAttackerIps(int limit) {
        return attackerIpCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
                .limit(limit)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue().get(),
                        (e1, e2) -> e1,
                        LinkedHashMap::new
                ));
    }

    public Map<Integer, Long> getTopTargetPorts(int limit) {
        return targetPortCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
                .limit(limit)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue().get(),
                        (e1, e2) -> e1,
                        LinkedHashMap::new
                ));
    }

    public String toJson(int blockedCount) {
        int score = calculateThreatScore();
        String level = getThreatLevel(score);

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"total_alerts\":").append(totalAlerts.get()).append(",");
        sb.append("\"packets_inspected\":").append(processedPackets.get()).append(",");
        sb.append("\"threat_score\":").append(score).append(",");
        sb.append("\"threat_level\":\"").append(level).append("\",");
        sb.append("\"quarantined_ips\":").append(blockedCount).append(",");

        // Severities
        sb.append("\"severities\":{");
        sb.append("\"LOW\":").append(severityCounts.getOrDefault("LOW", new AtomicLong(0)).get()).append(",");
        sb.append("\"MEDIUM\":").append(severityCounts.getOrDefault("MEDIUM", new AtomicLong(0)).get()).append(",");
        sb.append("\"HIGH\":").append(severityCounts.getOrDefault("HIGH", new AtomicLong(0)).get()).append(",");
        sb.append("\"CRITICAL\":").append(severityCounts.getOrDefault("CRITICAL", new AtomicLong(0)).get());
        sb.append("},");

        // Top IPs
        sb.append("\"top_attackers\":{");
        Map<String, Long> topIps = getTopAttackerIps(5);
        int idx = 0;
        for (Map.Entry<String, Long> e : topIps.entrySet()) {
            sb.append("\"").append(e.getKey()).append("\":").append(e.getValue());
            if (++idx < topIps.size()) sb.append(",");
        }
        sb.append("},");

        // Top Ports
        sb.append("\"top_ports\":{");
        Map<Integer, Long> topPorts = getTopTargetPorts(5);
        idx = 0;
        for (Map.Entry<Integer, Long> e : topPorts.entrySet()) {
            sb.append("\"").append(e.getKey()).append("\":").append(e.getValue());
            if (++idx < topPorts.size()) sb.append(",");
        }
        sb.append("},");

        // Protocols
        sb.append("\"protocols\":{");
        idx = 0;
        for (Map.Entry<String, AtomicLong> e : protocolCounts.entrySet()) {
            sb.append("\"").append(e.getKey()).append("\":").append(e.getValue().get());
            if (++idx < protocolCounts.size()) sb.append(",");
        }
        sb.append("}");

        sb.append("}");
        return sb.toString();
    }
}
