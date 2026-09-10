import json, re
from collections import defaultdict, OrderedDict

REP = r"E:\guardfox-ai-engine\control-driven-reports\control_driven_report_with_snippets_20260722_185113.json"
with open(REP, encoding="utf-8") as f:
    data = json.load(f)

findings = data["findings"]            # 122 confirmed
non = data["nonConfirmedFindings"]      # 303

GLOBAL_MARKERS = ["nooppasswordencoder","csrf.disable","csrf(csrf -> csrf.disable",
                 "session.invalidate","sessionfixation","webbsecurityconfig","nosalt","plaintext"]
LOCAL_SIGNALS = ["select ","concat","containskey","pincode","hardcoded","equals(","== null",
                "bypass","jwt"," userid","password =="]
AUTH_ENDPOINTS = ["login","auth","account","verify","register","security","session","token",
                  "password","credential","jwt","oauth","user"]

def short_handler(method):
    if not method: return ""
    last = method.rfind('.')
    if last < 0: return method
    prev = method.rfind('.', 0, last)
    if prev < 0: return method
    return method[prev+1:]

def loc_key(f):
    return (f.get("fileName") or "") + ":" + str(f.get("line")) + "#" + short_handler(f.get("method"))

def nz(s): return s or ""

# ---------- Point 1: groupMultiCwe on confirmed ----------
groups = OrderedDict()
for f in findings:
    groups.setdefault(loc_key(f), []).append(f)

merged_confirmed = 0
collapsed_multi = 0
for g in groups.values():
    merged_confirmed += 1
    if len(g) > 1:
        collapsed_multi += 1

print("=== Point 1: 同位置多 CWE 合并 ===")
print(f"原 confirmed 条数 = {len(findings)}")
print(f"合并后主发现条数 = {merged_confirmed}  (减少 {len(findings)-merged_confirmed})")
print(f"其中存在 >1 CWE 的合并组 = {collapsed_multi}")

# ---------- Points 2+3: consolidateGlobalAuth on confirmed ----------
config_files = set()  # 报告中无显式 configFile 字段；用 className 含 WebSecurityConfig 近似
# 把 WebSecurityConfig 作为权威锚点文件名（合成）
def is_config_file(fn):
    return fn is not None and "WebSecurityConfig" in fn

global_dup = []
kept_local = []
for f in findings:
    if f["cwe"] not in ("CWE-287","CWE-352"):
        continue
    ev = nz(f.get("sourceEvidence")).lower()
    cites = any(m in ev for m in GLOBAL_MARKERS)
    if not cites:
        kept_local.append(f); continue
    if is_config_file(f.get("fileName")):
        kept_local.append(f); continue
    cn = (f.get("className") or "").lower()
    if any(k in cn for k in AUTH_ENDPOINTS):
        kept_local.append(f); continue
    if any(s in ev for s in LOCAL_SIGNALS):
        kept_local.append(f); continue
    global_dup.append(f)

print("\n=== Points 2+3: 全局认证配置缺陷归因 ===")
print(f"CWE-287/CWE-352 候选(confirmed) = {len([f for f in findings if f['cwe'] in ('CWE-287','CWE-352')])}")
print(f"  将被归并(降级为重复)的端点数 = {len(global_dup)}")
print(f"  保留(本地认证逻辑/认证端点) = {len(kept_local)}")
print("被归并样例:")
for f in global_dup[:8]:
    print(f"   - {f['className']}.{f['method']}:{f['line']} {f['cwe']}")
print("保留样例(应为真实本地漏洞):")
for f in kept_local[:8]:
    print(f"   - {f['className']}.{f['method']}:{f['line']} {f['cwe']}")
