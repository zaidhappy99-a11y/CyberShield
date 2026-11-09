package com.netsentinel;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * NetSentinel Main Java SOC Analytics & API Server
 * High-performance, zero-dependency REST & Web Dashboard Server.
 */
public class NetSentinelServer {
    public static final int DEFAULT_PORT = 8080;
    private static final String WEB_ROOT = findWebRoot();

    private final QuarantineManager quarantineManager;
    private final NetworkStats networkStats;
    private final ThreatCorrelator threatCorrelator;
    private final int port;

    public NetSentinelServer(int port) {
        this.port = port;
        this.quarantineManager = new QuarantineManager();
        this.networkStats = new NetworkStats();
        this.threatCorrelator = new ThreatCorrelator(quarantineManager, networkStats);
    }

    public void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(16));

        // 1. Static Web Dashboard Handlers
        StaticFileHandler fileHandler = new StaticFileHandler(WEB_ROOT);
        server.createContext("/", fileHandler);

        // 2. Alert Ingestion & Query API
        server.createContext("/api/alerts", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                handleCors(exchange);
                String method = exchange.getRequestMethod().toUpperCase();

                if ("OPTIONS".equals(method)) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                if ("GET".equals(method)) {
                    String query = exchange.getRequestURI().getQuery();
                    int limit = 50;
                    String severity = "ALL";
                    if (query != null) {
                        for (String param : query.split("&")) {
                            String[] pair = param.split("=");
                            if (pair.length == 2) {
                                if ("limit".equalsIgnoreCase(pair[0])) {
                                    try { limit = Integer.parseInt(pair[1]); } catch (Exception ignored) {}
                                } else if ("severity".equalsIgnoreCase(pair[0])) {
                                    severity = pair[1];
                                }
                            }
                        }
                    }
                    List<SecurityAlert> alerts = threatCorrelator.getAlerts(limit, severity);
                    String json = threatCorrelator.alertsToJson(alerts);
                    sendResponse(exchange, 200, json, "application/json");
                } else if ("POST".equals(method)) {
                    String body = readBody(exchange);
                    if (!body.isEmpty()) {
                        SecurityAlert alert = SecurityAlert.fromJson(body);
                        threatCorrelator.processIncomingAlert(alert);
                        sendResponse(exchange, 201, "{\"status\":\"success\",\"id\":\"" + alert.getId() + "\"}", "application/json");
                    } else {
                        sendResponse(exchange, 400, "{\"error\":\"Empty alert payload\"}", "application/json");
                    }
                } else if ("DELETE".equals(method)) {
                    threatCorrelator.clearAlerts();
                    sendResponse(exchange, 200, "{\"status\":\"cleared\"}", "application/json");
                } else {
                    sendResponse(exchange, 405, "Method Not Allowed", "text/plain");
                }
            }
        });

        // 3. Telemetry Statistics API
        server.createContext("/api/stats", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                handleCors(exchange);
                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                String json = networkStats.toJson(quarantineManager.getBlockedCount());
                sendResponse(exchange, 200, json, "application/json");
            }
        });

        // 4. Active Defense / Quarantine API
        server.createContext("/api/quarantine", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                handleCors(exchange);
                String method = exchange.getRequestMethod().toUpperCase();
                if ("OPTIONS".equals(method)) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }

                if ("GET".equals(method)) {
                    sendResponse(exchange, 200, quarantineManager.toJson(), "application/json");
                } else if ("POST".equals(method)) {
                    String body = readBody(exchange);
                    String ip = extractField(body, "ip");
                    String reason = extractField(body, "reason");
                    String severity = extractField(body, "severity");
                    if (ip.isEmpty()) {
                        sendResponse(exchange, 400, "{\"error\":\"Missing IP\"}", "application/json");
                    } else {
                        quarantineManager.blockIp(ip, reason.isEmpty() ? "Manual SOC Block" : reason, severity);
                        sendResponse(exchange, 200, "{\"status\":\"blocked\",\"ip\":\"" + ip + "\"}", "application/json");
                    }
                } else if ("DELETE".equals(method)) {
                    String body = readBody(exchange);
                    String ip = extractField(body, "ip");
                    if (ip.isEmpty()) {
                        String query = exchange.getRequestURI().getQuery();
                        if (query != null && query.contains("ip=")) {
                            ip = query.split("ip=")[1].split("&")[0];
                        }
                    }
                    if (quarantineManager.unblockIp(ip)) {
                        sendResponse(exchange, 200, "{\"status\":\"unblocked\",\"ip\":\"" + ip + "\"}", "application/json");
                    } else {
                        sendResponse(exchange, 404, "{\"error\":\"IP not found in quarantine\"}", "application/json");
                    }
                }
            }
        });

        // 5. Trigger Attack Simulation API
        server.createContext("/api/simulate", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                handleCors(exchange);
                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    String body = readBody(exchange);
                    String attackType = extractField(body, "type");
                    if (attackType.isEmpty()) attackType = "portscan";

                    final String simType = attackType;
                    new Thread(() -> triggerPythonSimulation(simType)).start();

                    sendResponse(exchange, 200, "{\"status\":\"simulation_triggered\",\"type\":\"" + attackType + "\"}", "application/json");
                } else {
                    sendResponse(exchange, 405, "Method Not Allowed", "text/plain");
                }
            }
        });

        // 6. Forensic Incident Report Export API
        server.createContext("/api/export", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                handleCors(exchange);
                String csv = threatCorrelator.generateCsvReport();
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"netsentinel_report.csv\"");
                sendResponse(exchange, 200, csv, "text/csv; charset=UTF-8");
            }
        });

        server.start();
        System.out.println("======================================================================");
        System.out.println("  [NetSentinel Java SOC Server] Active and Listening on port " + port);
        System.out.println("  -> Web Dashboard: http://localhost:" + port + "/");
        System.out.println("  -> Alert Ingestion API: http://localhost:" + port + "/api/alerts");
        System.out.println("  -> Web Assets Directory: " + WEB_ROOT);
        System.out.println("======================================================================");
    }

    private void triggerPythonSimulation(String type) {
        try {
            String script = "import sys; sys.path.append('detector'); from attack_simulator import global_simulator; ";
            switch (type.toLowerCase()) {
                case "portscan":
                    script += "global_simulator.simulate_port_scan()";
                    break;
                case "dos":
                    script += "global_simulator.simulate_dos_flood()";
                    break;
                case "sqli":
                    script += "global_simulator.simulate_sqli_attack()";
                    break;
                case "xss":
                    script += "global_simulator.simulate_xss_attack()";
                    break;
                case "traversal":
                    script += "global_simulator.simulate_path_traversal()";
                    break;
                case "scanner":
                    script += "global_simulator.simulate_scanner_recon()";
                    break;
                case "bruteforce":
                    script += "global_simulator.simulate_brute_force()";
                    break;
                default:
                    script += "global_simulator.simulate_port_scan()";
            }

            File runPyBat = new File("run_python.bat");
            ProcessBuilder pb;
            if (runPyBat.exists()) {
                pb = new ProcessBuilder("cmd.exe", "/c", "run_python.bat", "-c", script);
            } else {
                pb = new ProcessBuilder("python", "-c", script);
            }
            pb.directory(new File("."));
            pb.inheritIO().start();
        } catch (Exception e) {
            System.err.println("[!] Failed to trigger Python simulation: " + e.getMessage());
        }
    }

    private static String findWebRoot() {
        File[] candidates = {
            new File("web"),
            new File("../web"),
            new File("CyberSecurity-Project/web")
        };
        for (File c : candidates) {
            if (c.exists() && c.isDirectory()) {
                return c.getAbsolutePath();
            }
        }
        return new File("web").getAbsolutePath();
    }

    private void handleCors(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    private String readBody(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[2048];
        int read;
        while ((read = is.read(buf)) != -1) {
            bos.write(buf, 0, read);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response, String contentType) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String extractField(String json, String field) {
        String pattern = "\"" + field + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1);
        }
        return "";
    }

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {}
        }

        try {
            NetSentinelServer server = new NetSentinelServer(port);
            server.start();
        } catch (IOException e) {
            System.err.println("[FATAL] Could not start NetSentinel Java Server: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
