# LogMind 🔍
### Observability Drift Tracking Engine

> LogMind is a single-file Python CLI tool that scans your log files, remembers what it has seen across runs, and tracks how issues evolve over time — surfacing what is **new**, **recurring**, **resolved**, or **forgotten**.

---

## 📑 Table of Contents
1. [What Makes It Different](#what-makes-it-different)
2. [Requirements](#requirements)
3. [Project Setup](#project-setup)
4. [Running LogMind](#running-logmind)
5. [All Commands](#all-commands)
6. [Output Files](#output-files)
7. [Advanced Scanning](#advanced-scanning)
8. [What LogMind Detects](#what-logmind-detects)
9. [Step-by-Step: Full Test from Scratch](#step-by-step-full-test-from-scratch)
10. [Folder Structure Reference](#folder-structure-reference)
11. [Health Score Reference](#health-score-reference)
12. [Tips](#tips)

---

## What Makes It Different

Most log tools tell you what is wrong **right now**.  
LogMind tells you what has **changed** since last time.

| Traditional Log Scanner | LogMind |
|:------------------------|:--------|
| Shows all current errors | Shows only what is NEW vs REPEATED |
| No memory between runs | Persistent drift memory across scans |
| No health tracking | 0–100 observability health score |
| No visual topology | Auto-opens interactive graph in browser |

---

## Requirements

- **Python 3.7 or higher** (no third-party packages needed)
- **Internet connection** (only for graph visualization in browser via GraphvizOnline)
- One file: `logmind.py`

Check your Python version:
```bash
python --version
```

---

## Project Setup

### Step 1 — Get the file

Save `logmind.py` to a folder on your computer. For example:

```text
C:\Users\YourName\Desktop\my-project\
    logmind.py
```

### Step 2 — Create a logs folder

Create a folder called `logs` (or any name you like) next to `logmind.py`:

```text
my-project\
    logmind.py
    logs\
```

### Step 3 — Add your log files

Put your log files inside the `logs` folder. LogMind reads these file types automatically:

```text
.log   .txt   .out   .err
.json  .yaml  .yml
.conf  .ini
```

**Option A — Use your own existing log files**  
Copy any `.log` or `.txt` files from your server, app, or system into the `logs` folder.

**Option B — Create a sample log file to test with**  
Create a file called `logs\app.log` and paste this inside it:

```log
2026-06-01 09:00:01 ERROR [db-service] [req-001] Database connection timeout after 30s
2026-06-01 09:00:05 INFO [api-gateway] [req-002] Routing request to billing-service
2026-06-01 09:00:07 INFO [billing-service] [req-003] Token verified: bearer secret_api_token_xyz
2026-06-01 09:00:09 WARN [payment-service] [req-004] Payment gateway timeout, retrying...
2026-06-01 09:00:15 FATAL [auth-service] [req-005] Critical crash during JWT decryption panic
This line has no timestamp and no request or trace id at all
2026-06-01 09:00:20 DEBUG [email-service] [req-006] Sending welcome email to user@example.com
```

**Option C — Download a real-world sample log**  
You can download any public log dataset and drop it into your `logs` folder. Some free sources:
- [LogHub Datasets](https://github.com/logpai/loghub) (copy any `.log` file)
- Your own application logs from `/var/log/` on Linux or `Event Viewer` on Windows

Your folder should look like this before running:

```text
my-project\
    logmind.py
    logs\
        app.log        ← your log file goes here
```

---

## Running LogMind

Open your terminal (PowerShell on Windows, Terminal on Mac/Linux).  
Navigate to your project folder:

```bash
cd C:\Users\YourName\Desktop\my-project
```

---

## All Commands

### `scan` — Scan your logs for issues

```bash
python logmind.py scan ./logs
```

This scans all files in the `logs` folder and prints a compact report.

**Example output:**
```text
LOGMIND SCAN #1
Path: ./logs
Files: 1
Issues: 9
Health: 22/100 CRITICAL

DRIFT
NEW        8
REPEATED   0
RESOLVED   0
STALE      0

TOP RISKS
[CRITICAL] 2026-06-01 09:00:15 FATAL [auth-service]...
[SECURITY] bearer secret_api_token_xyz in billing-service...
[ERROR]    Database connection timeout after 30s...

Report saved: ./logs/logmind_report.txt
```

**Run it a second time** (without changing the log file) to see drift kick in:

```bash
python logmind.py scan ./logs
```

```text
LOGMIND SCAN #2
Health: 22/100 CRITICAL

DRIFT
NEW        0
REPEATED   8     ← same issues seen again
RESOLVED   0
STALE      0
```

**What the fields mean:**

| Field | Meaning |
|:------|:--------|
| `Files` | Number of log files scanned |
| `Issues` | Total issue occurrences found |
| `Health` | Observability score from 0 (worst) to 100 (best) |
| `NEW` | Issues seen for the first time this scan |
| `REPEATED` | Issues that existed in a previous scan and are still present |
| `RESOLVED` | Issues from a previous scan that are no longer present |
| `STALE` | Issues not seen for 3+ consecutive scans (evicted from memory) |

---

### `graph` — Export and visualize the drift topology

```bash
python logmind.py graph ./logs
```

This scans the logs, updates the drift memory, generates a `logmind.dot` file, and **automatically opens an interactive visual graph in your browser**.

**What you see in the browser (GraphvizOnline):**

| Node/Edge Color | Meaning |
|:----------------|:--------|
| 🔴 Red node | Critical or Security issue |
| 🟠 Orange node | Error or Warning |
| 🟠 Orange border | Issue is REPEATED (seen before) |
| 🟢 Green node | RESOLVED issue |
| ⬜ Gray node | STALE issue (not seen in 3+ scans) |
| 🔵 Blue node | Source log file |
| `- - -` Dashed edge | Related issues (share similar keywords) |

> **Tip:** The graph also shows a LEGEND box in the bottom corner explaining all colors.

---

### `reset` — Clear drift memory and start fresh

```bash
python logmind.py reset ./logs
```

This deletes the `.logmind.json` cache file so the next scan treats everything as NEW again.

Use this when:
- You want to start a fresh baseline
- You have changed log files significantly
- You are beginning a new testing session

---

## Output Files

After scanning, LogMind creates these files inside your logs folder (these are automatically skipped in future scans):

| File | Description |
|:-----|:------------|
| `.logmind.json` | Hidden drift memory cache. Auto-updated on every scan. Do not edit. |
| `logmind_report.txt` | Full detailed scan report — open in Notepad or any text editor. |
| `logmind.dot` | Graph topology file — auto-opened in browser when you run `graph` mode. |

---

## Advanced Scanning

### Scanning a Single File
You can scan one specific file instead of a whole folder:
```bash
python logmind.py scan ./logs/app.log
```

### Scanning Any Path
You can point LogMind at any folder on your machine:
```bash
python logmind.py scan C:\MyApp\server-logs
python logmind.py graph C:\MyApp\server-logs
python logmind.py reset C:\MyApp\server-logs
```

---

## What LogMind Detects

LogMind automatically detects these issue categories in any log line:

| Category | Keywords / Patterns |
|:---------|:--------------------|
| **Critical** | `critical`, `crash`, `fatal`, `panic` |
| **Error** | `error`, `exception`, `traceback`, `failed`, `failure` |
| **Warning** | `warn`, `warning`, `timeout`, `retry` |
| **Security** | `secret`, `password`, `token`, `api_key`, `authorization`, `bearer` |
| **IP Address** | e.g. `192.168.1.1` |
| **Email** | e.g. `user@example.com` |
| **URL** | Any `http://` or `https://` link |
| **Missing Timestamp** | Lines with no recognizable date/time |
| **Missing Context ID** | Lines with no trace/request/session/correlation ID |

---

## Step-by-Step: Full Test from Scratch

```bash
# 1. Go to your project folder
cd C:\Users\YourName\Desktop\my-project

# 2. Create your logs folder and add a log file
mkdir logs
# (paste sample log content into logs\app.log)

# 3. Run first scan — establishes baseline
python logmind.py scan ./logs

# 4. Run second scan — see REPEATED issues appear
python logmind.py scan ./logs

# 5. Open the visual drift graph in your browser
python logmind.py graph ./logs

# 6. Read the full detailed report
notepad ./logs/logmind_report.txt

# 7. Reset memory and start fresh
python logmind.py reset ./logs
```

---

## Folder Structure Reference

```text
my-project\
│
├── logmind.py                  ← the engine (single file, no install needed)
│
└── logs\                       ← your log folder (any name works)
    ├── app.log                 ← your log files go here
    ├── server.log
    │
    ├── .logmind.json           ← auto-created: drift memory cache
    ├── logmind_report.txt      ← auto-created: full scan report
    └── logmind.dot             ← auto-created: graph topology file
```

---

## Health Score Reference

| Score | Risk Level | What It Means |
|:-----:|:----------:|:--------------|
| 85–100 | 🟢 LOW | System is healthy, minimal issues |
| 60–84 | 🟡 MED | Some recurring issues, worth monitoring |
| 35–59 | 🟠 HIGH | Significant errors or security concerns |
| 0–34 | 🔴 CRITICAL | Fatal crashes, active security issues, or severe drift |

Score is penalized by:
- Critical/Security issues (heaviest penalty)
- Errors and warnings
- Missing timestamps and trace/request IDs
- Repeated and stale unresolved issues

---

## Tips

- **Run scans regularly** on the same folder to build up drift history — the more scans, the richer the REPEATED/RESOLVED/STALE signals become.
- **Use `reset` sparingly** — resetting wipes all memory, so you lose the drift history.
- **The graph is most useful after 2+ scans** — that is when RESOLVED (green) and REPEATED (orange border) nodes appear.
- **`logmind_report.txt` has the full detail** — the terminal output is intentionally compact. Open the report file for complete issue lists.

**Folders LogMind Automatically Skips (Noise Reduction):**
`.git`, `node_modules`, `venv`, `__pycache__`, `dist`, `build`