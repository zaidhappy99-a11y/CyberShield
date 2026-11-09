"""
NetSentinel - Malicious Payload & Exploit Signatures Database
Contains regular expressions and heuristics for detecting signature-based attacks.
"""

import re
import math
from typing import Optional, Dict, Any

# Signature definitions with severity, description, and mitigation advice
SIGNATURE_RULES = [
    # --- SQL Injection Rules ---
    {
        "id": "SIG-SQLI-001",
        "name": "SQL Injection: Boolean / Tautology Attack",
        "regex": re.compile(r"('\s*OR\s*'1'='1'|'\s*OR\s*1=1|admin'\s*--|\"\s*OR\s*\"\"=\")", re.IGNORECASE),
        "attack_type": "SQL Injection",
        "severity": "HIGH",
        "cve": "CWE-89",
        "recommendation": "Use parameterized queries / prepared statements."
    },
    {
        "id": "SIG-SQLI-002",
        "name": "SQL Injection: UNION-based Data Extraction",
        "regex": re.compile(r"(UNION\s+(ALL\s+)?SELECT|SELECT\s+.*\s+FROM\s+INFORMATION_SCHEMA)", re.IGNORECASE),
        "attack_type": "SQL Injection",
        "severity": "CRITICAL",
        "cve": "CWE-89",
        "recommendation": "Block database schema enumeration; employ strict input validation."
    },
    {
        "id": "SIG-SQLI-003",
        "name": "SQL Injection: Time-Based / Out-of-Band Blind",
        "regex": re.compile(r"(WAITFOR\s+DELAY|SLEEP\(\s*\d+\s*\)|BENCHMARK\(\s*\d+)", re.IGNORECASE),
        "attack_type": "SQL Injection",
        "severity": "HIGH",
        "cve": "CWE-89",
        "recommendation": "Deploy Web Application Firewall (WAF) and restrict database execution time."
    },

    # --- Cross-Site Scripting (XSS) Rules ---
    {
        "id": "SIG-XSS-001",
        "name": "Cross-Site Scripting: Script Tag Injection",
        "regex": re.compile(r"(<script[\s>]|alert\(|javascript\s*:|document\.cookie)", re.IGNORECASE),
        "attack_type": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "cve": "CWE-79",
        "recommendation": "Sanitize and HTML-encode user inputs; implement Content Security Policy (CSP)."
    },
    {
        "id": "SIG-XSS-002",
        "name": "Cross-Site Scripting: Event Handler Vector",
        "regex": re.compile(r"(onload\s*=|onerror\s*=|onmouseover\s*=|eval\(|fetch\(.*attacker)", re.IGNORECASE),
        "attack_type": "Cross-Site Scripting (XSS)",
        "severity": "MEDIUM",
        "cve": "CWE-79",
        "recommendation": "Disallow unsafe inline handlers via strict CSP directives."
    },

    # --- Path Traversal & LFI Rules ---
    {
        "id": "SIG-TRAV-001",
        "name": "Directory / Path Traversal (LFI)",
        "regex": re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|c:\\boot\.ini)", re.IGNORECASE),
        "attack_type": "Path Traversal",
        "severity": "HIGH",
        "cve": "CWE-22",
        "recommendation": "Normalize file paths and restrict access within secure sandboxed roots."
    },

    # --- Command Injection / Remote Code Execution Rules ---
    {
        "id": "SIG-RCE-001",
        "name": "OS Command Injection Attempt",
        "regex": re.compile(r"(;\s*cat\s+/etc/|\|\s*bash\s+-i|cmd\.exe\s+/c|powershell(\.exe)?\s+-enc|/bin/sh|/bin/bash)", re.IGNORECASE),
        "attack_type": "Command Injection",
        "severity": "CRITICAL",
        "cve": "CWE-78",
        "recommendation": "Avoid passing user input directly into system command shells."
    },

    # --- Web Reconnaissance & Scanner Fingerprints ---
    {
        "id": "SIG-SCAN-001",
        "name": "Automated Security Scanner User-Agent",
        "regex": re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|acunetix|dirbuster|gobuster|wpscan|hydra)", re.IGNORECASE),
        "attack_type": "Reconnaissance Scan",
        "severity": "MEDIUM",
        "cve": "CWE-200",
        "recommendation": "Identify and block known malicious scanner fingerprints at edge proxy."
    },

    # --- Sensitive File / Endpoint Probing ---
    {
        "id": "SIG-PROBE-001",
        "name": "Sensitive Configuration & Git Repository Probing",
        "regex": re.compile(r"(\.env|/\.git/HEAD|/wp-config\.php|/actuator/env|/phpmyadmin|/shell\.php)", re.IGNORECASE),
        "attack_type": "Sensitive File Probing",
        "severity": "MEDIUM",
        "cve": "CWE-200",
        "recommendation": "Enforce strict web server access control rules (.htaccess / nginx denies)."
    }
]


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy to detect obfuscated payloads or encrypted DNS tunnels."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy


def match_payload_signatures(payload_str: str) -> Optional[Dict[str, Any]]:
    """Scan string representation of payload against signature database."""
    if not payload_str:
        return None

    for rule in SIGNATURE_RULES:
        match = rule["regex"].search(payload_str)
        if match:
            snippet = payload_str[max(0, match.start() - 20): min(len(payload_str), match.end() + 20)]
            return {
                "rule_id": rule["id"],
                "attack_type": rule["attack_type"],
                "severity": rule["severity"],
                "cve": rule["cve"],
                "recommendation": rule["recommendation"],
                "matched_text": match.group(0),
                "snippet": snippet.strip()
            }

    # Heuristic: Check for high-entropy obfuscation in long alphanumeric strings (possible DNS tunnel / shellcode)
    if (len(payload_str) > 120 and calculate_entropy(payload_str) > 5.5 
            and not payload_str.startswith("GET") and not payload_str.startswith("POST")
            and not "User-Agent" in payload_str):
        return {
            "rule_id": "HEUR-ENTROPY-001",
            "attack_type": "High Entropy Obfuscation / Tunneling",
            "severity": "LOW",
            "cve": "CWE-506",
            "recommendation": "Inspect binary/obfuscated network packet data.",
            "matched_text": "High entropy stream detected",
            "snippet": payload_str[:40] + "..."
        }

    return None
