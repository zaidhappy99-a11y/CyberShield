package com.netsentinel;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * NetSentinel Security Alert Data Model
 * Represents a detected network intrusion event.
 */
public class SecurityAlert {
    private String id;
    private String timestamp;
    private String sourceIp;
    private int sourcePort;
    private String destIp;
    private int destPort;
    private String protocol;
    private String attackType;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private String description;
    private String payloadPreview;
    private String actionTaken;
    private String recommendation;

    public SecurityAlert() {
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.actionTaken = "FLAGGED";
    }

    public SecurityAlert(String id, String sourceIp, int sourcePort, String destIp, int destPort,
                         String protocol, String attackType, String severity, String description,
                         String payloadPreview, String recommendation) {
        this.id = id;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.sourceIp = sourceIp;
        this.sourcePort = sourcePort;
        this.destIp = destIp;
        this.destPort = destPort;
        this.protocol = protocol;
        this.attackType = attackType;
        this.severity = severity != null ? severity.toUpperCase() : "LOW";
        this.description = description;
        this.payloadPreview = payloadPreview;
        this.actionTaken = "FLAGGED";
        this.recommendation = recommendation;
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public int getSourcePort() { return sourcePort; }
    public void setSourcePort(int sourcePort) { this.sourcePort = sourcePort; }

    public String getDestIp() { return destIp; }
    public void setDestIp(String destIp) { this.destIp = destIp; }

    public int getDestPort() { return destPort; }
    public void setDestPort(int destPort) { this.destPort = destPort; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getPayloadPreview() { return payloadPreview; }
    public void setPayloadPreview(String payloadPreview) { this.payloadPreview = payloadPreview; }

    public String getActionTaken() { return actionTaken; }
    public void setActionTaken(String actionTaken) { this.actionTaken = actionTaken; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }

    /**
     * Converts this alert to a JSON string without external libraries.
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"id\":\"").append(escapeJson(id)).append("\",");
        sb.append("\"timestamp\":\"").append(escapeJson(timestamp)).append("\",");
        sb.append("\"source_ip\":\"").append(escapeJson(sourceIp)).append("\",");
        sb.append("\"source_port\":").append(sourcePort).append(",");
        sb.append("\"dest_ip\":\"").append(escapeJson(destIp)).append("\",");
        sb.append("\"dest_port\":").append(destPort).append(",");
        sb.append("\"protocol\":\"").append(escapeJson(protocol)).append("\",");
        sb.append("\"attack_type\":\"").append(escapeJson(attackType)).append("\",");
        sb.append("\"severity\":\"").append(escapeJson(severity)).append("\",");
        sb.append("\"description\":\"").append(escapeJson(description)).append("\",");
        sb.append("\"payload_preview\":\"").append(escapeJson(payloadPreview)).append("\",");
        sb.append("\"action_taken\":\"").append(escapeJson(actionTaken)).append("\",");
        sb.append("\"recommendation\":\"").append(escapeJson(recommendation)).append("\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Parse simple JSON object into SecurityAlert.
     */
    public static SecurityAlert fromJson(String json) {
        SecurityAlert alert = new SecurityAlert();
        alert.setId(extractStringField(json, "id"));
        alert.setTimestamp(extractStringField(json, "timestamp"));
        alert.setSourceIp(extractStringField(json, "source_ip"));
        alert.setSourcePort(extractIntField(json, "source_port", 0));
        alert.setDestIp(extractStringField(json, "dest_ip"));
        alert.setDestPort(extractIntField(json, "dest_port", 0));
        alert.setProtocol(extractStringField(json, "protocol"));
        alert.setAttackType(extractStringField(json, "attack_type"));
        alert.setSeverity(extractStringField(json, "severity"));
        alert.setDescription(extractStringField(json, "description"));
        alert.setPayloadPreview(extractStringField(json, "payload_preview"));
        alert.setActionTaken(extractStringField(json, "action_taken"));
        alert.setRecommendation(extractStringField(json, "recommendation"));

        if (alert.getId() == null || alert.getId().isEmpty()) {
            alert.setId("ALT-" + System.currentTimeMillis());
        }
        if (alert.getSeverity() == null || alert.getSeverity().isEmpty()) {
            alert.setSeverity("MEDIUM");
        }
        return alert;
    }

    private static String extractStringField(String json, String field) {
        String pattern = "\"" + field + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1);
        }
        return "";
    }

    private static int extractIntField(String json, String field, int defaultValue) {
        String pattern = "\"" + field + "\"\\s*:\\s*([0-9]+)";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            try {
                return Integer.parseInt(m.group(1));
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
