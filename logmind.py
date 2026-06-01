"""
LogMind: Observability Drift Tracking Engine

High-Level Overview:
LogMind is a zero-dependency Python script designed to scan log files and track observability "drift" over time.
Instead of just showing current errors, it maintains a local JSON memory cache (`.logmind.json`) across runs to determine if issues are:
- NEW: Seen for the first time in the current scan.
- REPEATED: Seen in a previous scan and still present.
- RESOLVED: Seen in a previous scan but no longer present.
- STALE: Evicted from memory after missing 3 consecutive scans.

Key Features:
1. Scanning Mechanism: It walks through a directory to find log files (or reads a single file) and scans the last 200KB for speed.
2. Issue Detection: It uses regular expressions to detect critical errors, warnings, security risks (like tokens/passwords), IP addresses, emails, URLs, and structural issues like missing timestamps or context IDs.
3. Fingerprinting: It normalizes log messages (removing specific data like digits) and hashes them to create a unique fingerprint. This allows it to recognize the "same" issue even if the timestamp changes.
4. Scoring: It generates an Observability Health Score from 0 to 100 based on the severity of the found issues.
5. Graph Visualization: It can generate a DOT file mapping the topology of logs and issues, and automatically open an interactive Graphviz view in the browser.

Usage:
- python logmind.py scan ./logs  -> Scans and reports drift in terminal and logmind_report.txt.
- python logmind.py graph ./logs -> Scans and visually graphs drift in the browser.
- python logmind.py reset ./logs -> Clears the local `.logmind.json` cache.
"""

import os, re, hashlib, sys, json, webbrowser, urllib.parse; from collections import Counter

def logmind(path=".", mode="scan", q=""):
    # Define the path for the persistent memory cache
    cache_path = os.path.join(path if os.path.isdir(path) else ".", ".logmind.json")
    
    # Handle the "reset" command by deleting the existing memory cache
    if mode == "reset":
        try:
            if os.path.exists(cache_path): os.remove(cache_path)
            print("Memory cache reset successfully.")
        except Exception: pass
        return {}

    # Define directories and file extensions to include or skip during the scan
    skipped, exts = {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build'}, {'.log', '.txt', '.out', '.err', '.json', '.yaml', '.yml', '.conf', '.ini'}
    targets = []
    
    # Verify the provided path exists
    if not os.path.exists(path):
        print(f"Error: Path '{path}' does not exist.")
        return {}

    # Gather log files to scan (either a single file or a directory traversal)
    if os.path.isfile(path) and not os.path.basename(path).startswith(('.logmind', 'logmind_report')): 
        targets = [path]
    elif os.path.isdir(path):
        for r, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skipped] # Ignore noisy directories
            # Only add matching file extensions, excluding LogMind's own output files
            targets.extend(os.path.join(r, f) for f in files if os.path.splitext(f)[1].lower() in exts and not f.startswith(('.logmind', 'logmind_report')))

    # Initialize variables to keep track of scan statistics
    files_scanned, file_issues, cat_counts, fingerprints = 0, Counter(), Counter(), {}
    
    # Regular expressions for categorizing different types of issues
    pats = {
        "Critical": r'(?i)\b(critical|crash|fatal|panic)\b', 
        "Error": r'(?i)\b(error|exception|traceback|failed|failure)\b', 
        "Warning": r'(?i)\b(warn|warning|timeout|retry)\b', 
        "Security": r'(?i)\b(secret|password|token|api_key|authorization|bearer)\b', 
        "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 
        "Email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 
        "URL": r'\bhttps?://[^\s<>"]+\b'
    }
    
    # Regular expressions for structural observability checks (Timestamp and Context IDs)
    ts_pat, ctx_pat = r'\b(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', r'(?i)\b(trace|request|session|rid|tid|sid|uuid|correlation|id)\b|\b[0-9a-fA-F-]{8,}\b'

    # Process each discovered log file
    for filepath in targets:
        try:
            # Read only the last 200KB of the file for performance optimization
            size = os.path.getsize(filepath)
            with open(filepath, 'rb') as f:
                if size > 200 * 1024: f.seek(size - 200 * 1024)
                content = f.read().decode('utf-8', errors='ignore')
            files_scanned += 1
        except Exception: continue

        filename = os.path.basename(filepath)
        
        # Analyze the file content line by line
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str: continue
            
            # Find all issues in this line based on our predefined regex patterns
            issues = [(k, line_str) for k, p in pats.items() if re.search(p, line_str)]
            
            # Check for missing observability foundations (Timestamp or Context IDs)
            if not re.search(ts_pat, line_str): issues.append(("Missing Timestamp", line_str))
            if not re.search(ctx_pat, line_str): issues.append(("Missing Context ID", line_str))
            
            # Process each found issue to create a normalized, unique fingerprint
            for cat, raw in issues:
                # Remove digits to normalize dynamic values (e.g., "timeout after 30s" -> "timeout after s")
                norm = ' '.join(re.sub(r'\d+', '', raw.lower()).split())
                # Hash the category, normalized message, and filename to create a unique ID
                f_hash = hashlib.md5(f"{cat}:{norm}:{filename}".encode('utf-8', errors='ignore')).hexdigest()
                
                # Track occurrence count for each unique fingerprint
                if f_hash not in fingerprints: 
                    fingerprints[f_hash] = {"type": cat, "msg": raw, "count": 0, "file": filename}
                
                fingerprints[f_hash]["count"] += 1
                file_issues[filepath] += 1
                cat_counts[cat] += 1

    # Load persistent drift memory from previous runs
    scan_idx, memory = 1, {}
    try:
        if os.path.exists(cache_path):
            with open(cache_path, 'r', encoding='utf-8') as f: 
                d = json.load(f)
                scan_idx = d.get("scan_idx", 0) + 1
                memory = d.get("memory", {})
    except Exception: pass

    # Compare current fingerprints against memory to determine DRIFT (New, Repeated, Resolved, Stale)
    new_c, rep_c, res_c, sta_c = 0, 0, 0, 0
    updated_memory = {}
    
    # Step 1: Check what is New or Repeated based on current fingerprints
    for fh, info in fingerprints.items():
        if fh not in memory:
            # First time seeing this issue
            new_c += 1
            updated_memory[fh] = {"first_seen": scan_idx, "last_seen": scan_idx, "count": info["count"], "type": info["type"], "file": info["file"], "msg": info["msg"]}
        else:
            # Issue has been seen before
            rep_c += 1
            updated_memory[fh] = {**memory[fh], "last_seen": scan_idx, "count": memory[fh]["count"] + info["count"]}
            
    # Step 2: Check memory for things we didn't see this time (Resolved or Stale)
    for fh, info in memory.items():
        if fh not in fingerprints:
            if scan_idx - info["last_seen"] >= 3: 
                # Issue hasn't been seen for 3+ scans, mark as Stale (drop from memory)
                sta_c += 1
            else: 
                # Issue wasn't seen this time, mark as Resolved (keep in memory temporarily)
                res_c += 1
                updated_memory[fh] = info

    # Save the updated memory back to the cache
    try:
        with open(cache_path, 'w', encoding='utf-8') as f: 
            json.dump({"scan_idx": scan_idx, "memory": updated_memory}, f)
    except Exception: pass

    # Calculate Observability Health Score (0-100) based on severity penalties
    p_sec = (cat_counts["Critical"] + cat_counts["Security"]) * 15
    p_err = cat_counts["Error"] * 8
    p_warn = cat_counts["Warning"] * 4
    p_miss = (cat_counts["Missing Timestamp"] + cat_counts["Missing Context ID"]) * 2
    
    score = max(0, min(100, int(100 - (p_sec + p_err + p_warn + p_miss + rep_c * 1 + sta_c * 0.5))))
    risk_level = "LOW" if score >= 85 else ("MED" if score >= 60 else ("HIGH" if score >= 35 else "CRITICAL"))
    main_risk = cat_counts.most_common(1)[0][0] if cat_counts else "None"

    # If the user requested the visual graph
    if mode == "graph":
        # Combine current and historical items for graphing
        graph_items = {fh: {"type": info["type"], "msg": info["msg"], "file": info["file"], "status": "NEW" if fh not in memory else "REPEATED"} for fh, info in fingerprints.items()}
        for fh, info in memory.items():
            if fh not in fingerprints: 
                graph_items[fh] = {"type": info["type"], "msg": info["msg"], "file": info["file"], "status": "STALE" if scan_idx - info["last_seen"] >= 3 else "RESOLVED"}
                
        # Calculate text similarity to draw "related" dashed lines between similar issues
        top_30, similarity_edges = list(graph_items.items())[:30], []
        for i in range(len(top_30)):
            for j in range(i + 1, len(top_30)):
                w1 = set(w for w in re.findall(r'\b[a-zA-Z]{4,}\b', top_30[i][1]["msg"].lower()))
                w2 = set(w for w in re.findall(r'\b[a-zA-Z]{4,}\b', top_30[j][1]["msg"].lower()))
                if len(w1 & w2) >= 2: 
                    similarity_edges.append((top_30[i][0], top_30[j][0]))

        # Sort graph nodes by severity priority and status weight
        pri, st_w = {"Critical": 5, "Security": 5, "Error": 4, "Warning": 3, "Missing Timestamp": 2, "Missing Context ID": 2}, {"NEW": 4, "REPEATED": 3, "RESOLVED": 2, "STALE": 1}
        sorted_items = sorted(graph_items.items(), key=lambda x: (-pri.get(x[1]["type"], 1), -st_w.get(x[1]["status"], 1)))

        # Build Graphviz DOT syntax
        dot_lines = ["digraph LogMind {", '  rankdir=LR;', '  node [shape=box, style=filled];', '  label="LogMind Observability Drift Graph";', '  labelloc=top;', '  fontsize=20;']
        
        # Add log files as root nodes
        for f in set(info["file"] for info in graph_items.values()):
            dot_lines.append(f'  "{f}" [fillcolor=lightblue, color=blue];')
            
        # Add issue nodes and connect them to their source files
        for fh, info in sorted_items:
            status, type_ = info["status"], info["type"]
            # Color logic based on severity and status
            fill = "red" if type_ in ("Critical", "Security") else ("green" if status == "RESOLVED" else ("gray" if status == "STALE" else "orange"))
            border = "darkorange" if status == "REPEATED" else ("red" if type_ in ("Critical", "Security") else ("green" if status == "RESOLVED" else ("gray" if status == "STALE" else "black")))
            
            # Clean up message text for better graph rendering
            clean = re.sub(ctx_pat, '', re.sub(ts_pat, '', info["msg"]))
            clean = ' '.join(re.sub(r'[\[\]:]', '', re.sub(r'(?i)\b(ERROR|WARN|INFO|DEBUG|FATAL|PANIC|CRITICAL|SECURITY)\b', '', clean)).split())
            lbl = f"{type_}: {clean}"
            lbl = (lbl[:42] + "..." if len(lbl) > 45 else lbl).replace('"', '\\"')
            
            dot_lines.append(f'  "{fh}" [label="{lbl}", fillcolor={fill}, color={border}, penwidth=2];')
            dot_lines.append(f'  "{info["file"]}" -> "{fh}";')
            
        # Add related edges
        for fh1, fh2 in similarity_edges:
            dot_lines.append(f'  "{fh1}" -> "{fh2}" [label="related", style=dashed, color=gray50, fontcolor=gray40];')
            
        # Add a legend for the graph
        dot_lines.extend([
            '  subgraph cluster_legend { label="LEGEND"; color=gray;',
            '    "Red" [label="Critical/Security", fillcolor=red, color=red, style=filled];',
            '    "Orange" [label="NEW/Error/Warning (Orange Border = Repeated)", fillcolor=orange, color=darkorange, penwidth=2, style=filled];',
            '    "Green" [label="Resolved", fillcolor=green, color=green, style=filled];',
            '    "Gray" [label="Stale", fillcolor=gray, color=gray, style=filled];',
            '  }',
            '}'
        ])

        # Write DOT file and automatically open in web browser
        try:
            dot_path = os.path.join(path if os.path.isdir(path) else ".", "logmind.dot")
            dot_content = '\n'.join(dot_lines)
            with open(dot_path, 'w', encoding='utf-8') as f: f.write(dot_content)
            webbrowser.open(f"https://dreampuf.github.io/GraphvizOnline/#{urllib.parse.quote(dot_content)}")
        except Exception: print("Warning: Could not write graph DOT file.")

    # Generate the comprehensive text report
    top_risks = sorted(fingerprints.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    rep_lines = [
        f"LOGMIND SCAN #{scan_idx}", f"Path: {path}", f"Files: {files_scanned}", f"Issues: {sum(file_issues.values())}", f"Health: {score}/100 {risk_level}", "",
        "DRIFT", f"NEW        {new_c}", f"REPEATED   {rep_c}", f"RESOLVED   {res_c}", f"STALE      {sta_c}", "", "TOP RISKS"
    ]
    for fh, info in top_risks: rep_lines.append(f"[{info['type'].upper()}] in {info['file']}: {info['msg']}")
    rep_lines.extend(["", "CATEGORY SUMMARY"] + [f"{cat:<18} {c}" for cat, c in cat_counts.most_common()] + ["", "TOP FILES"] + [f"{os.path.basename(fp):<18} {c} issues" for fp, c in file_issues.most_common()])
    
    # Save the report to disk
    try:
        report_path = os.path.join(path if os.path.isdir(path) else ".", "logmind_report.txt")
        with open(report_path, 'w', encoding='utf-8') as f: f.write("\n".join(rep_lines))
    except Exception: pass

    # Output CLI interface response
    if mode == "graph":
        print(f"Graph exported: {os.path.join(path if os.path.isdir(path) else '.', 'logmind.dot').replace(os.sep, '/')}")
        print("Opened graph file in browser.")
    else:
        # Compact terminal output
        print(f"\nLOGMIND SCAN #{scan_idx}\nPath: {path}\nFiles: {files_scanned}\nIssues: {sum(file_issues.values())}\nHealth: {score}/100 {risk_level}\n\nDRIFT\nNEW        {new_c}\nREPEATED   {rep_c}\nRESOLVED   {res_c}\nSTALE      {sta_c}\n\nTOP RISKS")
        for fh, info in top_risks[:3]: print(f"[{info['type'].upper()}] {info['msg'][:50]}...")
        print(f"\nReport saved: {report_path.replace(os.sep, '/')}")

    # Return stats dict for programmatic usage
    return {"files_scanned": files_scanned, "total_issues": sum(file_issues.values()), "file_issues": dict(file_issues), "category_counts": dict(cat_counts), "fingerprints": fingerprints, "drift": {"new": new_c, "repeated": rep_c, "resolved": res_c, "stale": sta_c}, "health": {"score": score, "risk": risk_level, "main_risk": main_risk}}

# Standard CLI Entrypoint
if __name__ == "__main__":
    # Parse CLI arguments to determine Mode (scan, reset, graph) and Path
    m = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in ("scan", "reset", "graph") else "scan"
    logmind(path=sys.argv[2] if len(sys.argv) > 2 and m == sys.argv[1] else (sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] not in ("scan", "reset", "graph") else "."), mode=m)
