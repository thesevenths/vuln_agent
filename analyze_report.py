import json, collections, re

REP = r"E:\guardfox-ai-engine\control-driven-reports\control_driven_report_with_snippets_20260722_185113.json"
with open(REP, encoding="utf-8") as f:
    data = json.load(f)

findings = data["findings"] + data["nonConfirmedFindings"]

def lockey(f):
    return f"{f.get('className','')}.{f.get('method','')}:{f.get('line','')}"

def filekey(f):
    return f"{f.get('fileName','')}:{f.get('line','')}"

# ---- Point 1: multi-CWE at same location ----
byloc = collections.defaultdict(list)
for f in findings:
    byloc[lockey(f)].append(f)

multi = {k: v for k, v in byloc.items() if len({x['cwe'] for x in v}) >= 2}
print("=== POINT 1: locations with >=2 distinct CWE ===")
print(f"total locations={len(byloc)}  multi-CWE locations={len(multi)}")
print()
# measure evidence distinctness within a location
def norm(s):
    return re.sub(r'\s+', ' ', (s or '')).strip().lower()[:160]

inflation = 0
legit = 0
for k, fs in sorted(multi.items(), key=lambda kv: -len({x['cwe'] for x in kv[1]})):
    cwes = [x['cwe'] for x in fs]
    evs = [norm(x.get('sourceEvidence','')) for x in fs]
    rts = [norm(x.get('reasoningTrace','')) for x in fs]
    distinct_ev = len(set(evs))
    distinct_rt = len(set(rts))
    tag = "?" 
    if distinct_ev <= 1:
        inflation += 1
        tag = "INFLATION(same evidence)"
    else:
        legit += 1
        tag = "DISTINCT"
    print(f"[{tag}] {k}  CWEs={cwes}  verdicts={[x['refutationVerdict'] for x in fs]}")
    print(f"        distinctEvidenceFragments={distinct_ev}/{len(evs)}  distinctReasoning={distinct_rt}/{len(rts)}")

print()
print(f">> multi-CWE locations: inflation(same-evidence)={inflation}  distinct-evidence={legit}")

# ---- dump the x4 example in detail ----
print("\n=== DETAIL: IDOREditOtherProfile.completed:40 ===")
for f in byloc.get("IDOREditOtherProfile.completed:40", []):
    print(f"--- CWE={f['cwe']} verdict={f['refutationVerdict']} conf={f.get('confidence')}")
    print("  evidence:", (f.get('sourceEvidence') or '')[:300].replace('\n',' '))
    print("  reasoning:", (f.get('reasoningTrace') or '')[:300].replace('\n',' '))
    print("  principle:", (f.get('principle') or '')[:160].replace('\n',' '))

# ---- Point 3: CWE-287 cluster evidence ----
print("\n=== POINT 3: CWE-287 evidence clustering ===")
c287 = [f for f in findings if f['cwe'] == 'CWE-287']
print(f"CWE-287 count={len(c287)}")
ev_counter = collections.Counter()
for f in c287:
    ev = norm(f.get('sourceEvidence',''))
    # crude fingerprint: first 120 chars
    ev_counter[ev[:120]] += 1
print("top evidence fingerprints:")
for ev, c in ev_counter.most_common(8):
    print(f"  x{c}: {ev[:110]}")
# how many share the single most common fingerprint
top = ev_counter.most_common(1)[0]
print(f"most-common fingerprint shared by {top[1]}/{len(c287)} CWE-287 findings")

# ---- Point 4: rejected but reasoning describes exploit ----
print("\n=== POINT 4: nonConfirmed with exploit-like reasoning ===")
keywords = ['利用', 'exploit', '攻击', 'bypass', '伪造', '伪造', '越权', '未授权', '可', '直接调用']
for f in data["nonConfirmedFindings"]:
    rt = f.get('reasoningTrace') or ''
    ev = f.get('sourceEvidence') or ''
    blob = (rt + ' ' + ev).lower()
    if any(k.lower() in blob for k in keywords) and len(rt) > 200:
        print(f"  {lockey(f)} CWE={f['cwe']} verdict={f['refutationVerdict']} conf={f.get('confidence')}")
        print(f"     reasoning: {rt[:260].replace(chr(10),' ')}")
