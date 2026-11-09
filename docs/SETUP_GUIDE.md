# NetSentinel Setup & Quick Start Guide

This guide walks you through compiling, running, and demonstrating NetSentinel on Windows, Linux, or macOS.

---

## 1. Prerequisites

- **Python**: Python 3.8+ (The project automatically discovers and uses Python).
- **Java (Optional for standalone mode, required for Java backend)**: JDK 11, 17, or 21+.
  - Recommended free JDKs: [Eclipse Temurin](https://adoptium.net/) or Microsoft OpenJDK.
- **Web Browser**: Any modern browser (Chrome, Edge, Firefox, Opera, Brave).

---

## 2. Quick Start (1-Click Launch)

To start the complete system immediately:

1. Double-click **`start_all.bat`** (or execute in PowerShell: `.\start_all.bat`).
2. The script will:
   - Launch the NetSentinel SOC Server on port `8080`.
   - Open your browser to `http://localhost:8080/`.
3. You can click any attack button in the **Cyber Attack Simulation Console** (e.g. *⚡ SYN Port Scan*, *💥 DoS SYN Flood*, *💉 SQL Injection*) to immediately observe live intrusion alerts and defense metrics!

---

## 3. Compiling & Running the Java Backend

If you have JDK installed and want to run the pure Java correlation backend:

### Step 1: Compile Java Source
Open a terminal in `backend/` and run:
```cmd
build.bat
```
*(Or manually: `javac -encoding UTF-8 -d bin src/com/netsentinel/*.java`)*

### Step 2: Start Java Server
```cmd
run.bat
```
*(Or manually: `java -cp bin com.netsentinel.NetSentinelServer 8080`)*

The Java server will start on port 8080 and serve the Web Dashboard and REST APIs.

### Step 3: Run the Python Detection Engine / Attack Simulator
In a second terminal window, run:
```cmd
run_python.bat detector\attack_simulator.py
```
The Python detector will inspect packets, detect intrusions, and dispatch JSON alerts directly to the Java backend at `http://localhost:8080/api/alerts`!

---

## 4. Running the Standalone Python Bridge

If you don't have Java JDK installed yet on your system, you can run the entire project out-of-the-box using the built-in Python Bridge:

```cmd
run_python.bat detector\bridge_server.py 8080
```

This starts the identical REST API and serves the same high-tech CSS SOC dashboard at `http://localhost:8080/`.

---

## 5. Running the Automated Test Suite

To verify all components (signatures, behavioral detection, frontend files, and Java classes):

```cmd
run_python.bat tests\test_system.py
```
Expected output:
```
==========================================================
  ALL 5 TEST SUITES PASSED SUCCESSFULLY! (100% READY)
==========================================================
```
