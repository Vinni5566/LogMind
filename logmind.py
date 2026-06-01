import os, re, hashlib, sys, json, webbrowser, urllib.parse; from collections import Counter

def logmind(path=".", mode="scan", q=""):
    cache_path = os.path.join(path if os.path.isdir(path) else ".", ".logmind.json")
    if mode == "reset":
        try:
            if os.path.exists(cache_path): os.remove(cache_path)
            print("Memory cache reset successfully.")
        except Exception: pass
        return {}

    skipped, exts = {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build'}, {'.log', '.txt', '.out', '.err', '.json', '.yaml', '.yml', '.conf', '.ini'}
    targets = []
    if not os.path.exists(path):
        print(f"Error: Path '{path}' does not exist.")
        return {}

    if os.path.isfile(path) and not os.path.basename(path).startswith(('.logmind', 'logmind_report')): targets = [path]
    elif os.path.isdir(path):
        for r, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skipped]
            targets.extend(os.path.join(r, f) for f in files if os.path.splitext(f)[1].lower() in exts and not f.startswith(('.logmind', 'logmind_report')))

    files_scanned, file_issues, cat_counts, fingerprints = 0, Counter(), Counter(), {}
    pats = {"Critical": r'(?i)\b(critical|crash|fatal|panic)\b', "Error": r'(?i)\b(error|exception|traceback|failed|failure)\b', "Warning": r'(?i)\b(warn|warning|timeout|retry)\b', "Security": r'(?i)\b(secret|password|token|api_key|authorization|bearer)\b', "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "Email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', "URL": r'\bhttps?://[^\s<>"]+\b'}
    ts_pat, ctx_pat = r'\b(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', r'(?i)\b(trace|request|session|rid|tid|sid|uuid|correlation|id)\b|\b[0-9a-fA-F-]{8,}\b'

    for filepath in targets:
        try:
            size = os.path.getsize(filepath)
            with open(filepath, 'rb') as f:
                if size > 200 * 1024: f.seek(size - 200 * 1024)
                content = f.read().decode('utf-8', errors='ignore')
            files_scanned += 1
        except Exception: continue

        filename = os.path.basename(filepath)
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str: continue
            issues = [(k, line_str) for k, p in pats.items() if re.search(p, line_str)]
            if not re.search(ts_pat, line_str): issues.append(("Missing Timestamp", line_str))
            if not re.search(ctx_pat, line_str): issues.append(("Missing Context ID", line_str))
            for cat, raw in issues:
                norm = ' '.join(re.sub(r'\d+', '', raw.lower()).split())
                f_hash = hashlib.md5(f"{cat}:{norm}:{filename}".encode('utf-8', errors='ignore')).hexdigest()
                if f_hash not in fingerprints: fingerprints[f_hash] = {"type": cat, "msg": raw, "count": 0, "file": filename}
                fingerprints[f_hash]["count"] += 1; file_issues[filepath] += 1; cat_counts[cat] += 1

    scan_idx, memory = 1, {}
    try:
        if os.path.exists(cache_path):
            with open(cache_path, 'r', encoding='utf-8') as f: d = json.load(f); scan_idx = d.get("scan_idx", 0) + 1; memory = d.get("memory", {})
    except Exception: pass

    new_c, rep_c, res_c, sta_c = 0, 0, 0, 0
    updated_memory = {}
    for fh, info in fingerprints.items():
        if fh not in memory:
            new_c += 1; updated_memory[fh] = {"first_seen": scan_idx, "last_seen": scan_idx, "count": info["count"], "type": info["type"], "file": info["file"], "msg": info["msg"]}
        else:
            rep_c += 1; updated_memory[fh] = {**memory[fh], "last_seen": scan_idx, "count": memory[fh]["count"] + info["count"]}
    for fh, info in memory.items():
        if fh not in fingerprints:
            if scan_idx - info["last_seen"] >= 3: sta_c += 1
            else: res_c += 1; updated_memory[fh] = info

    try:
        with open(cache_path, 'w', encoding='utf-8') as f: json.dump({"scan_idx": scan_idx, "memory": updated_memory}, f)
    except Exception: pass

    p_sec, p_err, p_warn = (cat_counts["Critical"] + cat_counts["Security"]) * 15, cat_counts["Error"] * 8, cat_counts["Warning"] * 4
    p_miss = (cat_counts["Missing Timestamp"] + cat_counts["Missing Context ID"]) * 2
    score = max(0, min(100, int(100 - (p_sec + p_err + p_warn + p_miss + rep_c * 1 + sta_c * 0.5))))
    risk_level = "LOW" if score >= 85 else ("MED" if score >= 60 else ("HIGH" if score >= 35 else "CRITICAL"))
    main_risk = cat_counts.most_common(1)[0][0] if cat_counts else "None"

    if mode == "graph":
        graph_items = {fh: {"type": info["type"], "msg": info["msg"], "file": info["file"], "status": "NEW" if fh not in memory else "REPEATED"} for fh, info in fingerprints.items()}
        for fh, info in memory.items():
            if fh not in fingerprints: graph_items[fh] = {"type": info["type"], "msg": info["msg"], "file": info["file"], "status": "STALE" if scan_idx - info["last_seen"] >= 3 else "RESOLVED"}
        top_30, similarity_edges = list(graph_items.items())[:30], []
        for i in range(len(top_30)):
            for j in range(i + 1, len(top_30)):
                w1 = set(w for w in re.findall(r'\b[a-zA-Z]{4,}\b', top_30[i][1]["msg"].lower()))
                w2 = set(w for w in re.findall(r'\b[a-zA-Z]{4,}\b', top_30[j][1]["msg"].lower()))
                if len(w1 & w2) >= 2: similarity_edges.append((top_30[i][0], top_30[j][0]))

        pri, st_w = {"Critical": 5, "Security": 5, "Error": 4, "Warning": 3, "Missing Timestamp": 2, "Missing Context ID": 2}, {"NEW": 4, "REPEATED": 3, "RESOLVED": 2, "STALE": 1}
        sorted_items = sorted(graph_items.items(), key=lambda x: (-pri.get(x[1]["type"], 1), -st_w.get(x[1]["status"], 1)))

        dot_lines = ["digraph LogMind {", '  rankdir=LR;', '  node [shape=box, style=filled];', '  label="LogMind Observability Drift Graph";', '  labelloc=top;', '  fontsize=20;']
        for f in set(info["file"] for info in graph_items.values()):
            dot_lines.append(f'  "{f}" [fillcolor=lightblue, color=blue];')
        for fh, info in sorted_items:
            status, type_ = info["status"], info["type"]
            fill = "red" if type_ in ("Critical", "Security") else ("green" if status == "RESOLVED" else ("gray" if status == "STALE" else "orange"))
            border = "darkorange" if status == "REPEATED" else ("red" if type_ in ("Critical", "Security") else ("green" if status == "RESOLVED" else ("gray" if status == "STALE" else "black")))
            clean = re.sub(ctx_pat, '', re.sub(ts_pat, '', info["msg"]))
            clean = ' '.join(re.sub(r'[\[\]:]', '', re.sub(r'(?i)\b(ERROR|WARN|INFO|DEBUG|FATAL|PANIC|CRITICAL|SECURITY)\b', '', clean)).split())
            lbl = f"{type_}: {clean}"
            lbl = (lbl[:42] + "..." if len(lbl) > 45 else lbl).replace('"', '\\"')
            dot_lines.append(f'  "{fh}" [label="{lbl}", fillcolor={fill}, color={border}, penwidth=2];')
            dot_lines.append(f'  "{info["file"]}" -> "{fh}";')
        for fh1, fh2 in similarity_edges:
            dot_lines.append(f'  "{fh1}" -> "{fh2}" [label="related", style=dashed, color=gray50, fontcolor=gray40];')
        dot_lines.extend([
            '  subgraph cluster_legend { label="LEGEND"; color=gray;',
            '    "Red" [label="Critical/Security", fillcolor=red, color=red, style=filled];',
            '    "Orange" [label="NEW/Error/Warning (Orange Border = Repeated)", fillcolor=orange, color=darkorange, penwidth=2, style=filled];',
            '    "Green" [label="Resolved", fillcolor=green, color=green, style=filled];',
            '    "Gray" [label="Stale", fillcolor=gray, color=gray, style=filled];',
            '  }',
            '}'
        ])

        try:
            dot_path = os.path.join(path if os.path.isdir(path) else ".", "logmind.dot")
            dot_content = '\n'.join(dot_lines)
            with open(dot_path, 'w', encoding='utf-8') as f: f.write(dot_content)
            webbrowser.open(f"https://dreampuf.github.io/GraphvizOnline/#{urllib.parse.quote(dot_content)}")
        except Exception: print("Warning: Could not write graph DOT file.")

    top_risks = sorted(fingerprints.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    rep_lines = [
        f"LOGMIND SCAN #{scan_idx}", f"Path: {path}", f"Files: {files_scanned}", f"Issues: {sum(file_issues.values())}", f"Health: {score}/100 {risk_level}", "",
        "DRIFT", f"NEW        {new_c}", f"REPEATED   {rep_c}", f"RESOLVED   {res_c}", f"STALE      {sta_c}", "", "TOP RISKS"
    ]
    for fh, info in top_risks: rep_lines.append(f"[{info['type'].upper()}] in {info['file']}: {info['msg']}")
    rep_lines.extend(["", "CATEGORY SUMMARY"] + [f"{cat:<18} {c}" for cat, c in cat_counts.most_common()] + ["", "TOP FILES"] + [f"{os.path.basename(fp):<18} {c} issues" for fp, c in file_issues.most_common()])
    
    try:
        report_path = os.path.join(path if os.path.isdir(path) else ".", "logmind_report.txt")
        with open(report_path, 'w', encoding='utf-8') as f: f.write("\n".join(rep_lines))
    except Exception: pass

    if mode == "graph":
        print(f"Graph exported: {os.path.join(path if os.path.isdir(path) else '.', 'logmind.dot').replace(os.sep, '/')}")
        print("Opened graph file in browser.")
    else:
        print(f"\nLOGMIND SCAN #{scan_idx}\nPath: {path}\nFiles: {files_scanned}\nIssues: {sum(file_issues.values())}\nHealth: {score}/100 {risk_level}\n\nDRIFT\nNEW        {new_c}\nREPEATED   {rep_c}\nRESOLVED   {res_c}\nSTALE      {sta_c}\n\nTOP RISKS")
        for fh, info in top_risks[:3]: print(f"[{info['type'].upper()}] {info['msg'][:50]}...")
        print(f"\nReport saved: {report_path.replace(os.sep, '/')}")

    return {"files_scanned": files_scanned, "total_issues": sum(file_issues.values()), "file_issues": dict(file_issues), "category_counts": dict(cat_counts), "fingerprints": fingerprints, "drift": {"new": new_c, "repeated": rep_c, "resolved": res_c, "stale": sta_c}, "health": {"score": score, "risk": risk_level, "main_risk": main_risk}}

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in ("scan", "reset", "graph") else "scan"
    logmind(path=sys.argv[2] if len(sys.argv) > 2 and m == sys.argv[1] else (sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] not in ("scan", "reset", "graph") else "."), mode=m)
