import json
REP = r"E:\guardfox-ai-engine\control-driven-reports\control_driven_report_with_snippets_20260722_185113.json"
with open(REP, encoding="utf-8") as f:
    data = json.load(f)
allf = data["findings"] + data["nonConfirmedFindings"]

def show(f, tag=""):
    print(f"\n##### {tag} {f['className']}.{f['method']}:{f['line']}  CWE={f['cwe']} verdict={f['refutationVerdict']} conf={f.get('confidence')}")
    for k in ("sourceEvidence","reasoningTrace","callChain","exploitPoc"):
        v = f.get(k) or ""
        print(f"  [{k}] ({len(v)}): {v[:500].replace(chr(10),' ')}")

# Point 1 detail: completed:40 (both key variants)
targets = ["IDOREditOtherProfile.IDOREditOtherProfile.completed:40",
           ".org.owasp.webgoat.lessons.idor.IDOREditOtherProfile.completed:40"]
for t in targets:
    for f in allf:
        if f["className"]+".'"+f["method"]+":"+str(f["line"]) == t.replace(".completed", "'.completed") or \
           (f["className"]+"."+f["method"]+":"+str(f["line"])) == t:
            show(f, "P1")

# Point 3: sample CWE-287 evidence
print("\n\n========== POINT 3: CWE-287 sample evidence ==========")
c287 = [f for f in allf if f["cwe"]=="CWE-287"]
print(f"total CWE-287 = {len(c287)}")
for f in c287[:6]:
    show(f, "CWE-287")

# Point 4: the 3 specific cases
print("\n\n========== POINT 4: rejected-but-exploitable cases ==========")
locs = ["JWTRefreshEndpoint.JWTRefreshEndpoint.newToken:108",
        "SpoofCookieAssignment.SpoofCookieAssignment.login:46"]
for t in locs:
    for f in data["nonConfirmedFindings"]:
        if f["className"]+"."+f["method"]+":"+str(f["line"]) == t:
            show(f, "P4-rej")
# CWE-840 at line 40 (likely IDOREditOtherProfile.completed:40 one of its CWE-840)
for f in data["nonConfirmedFindings"]:
    if f["cwe"]=="CWE-840" and f["line"]==40:
        show(f, "P4-CWE840:40")
