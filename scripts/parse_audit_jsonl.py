import json
from collections import Counter

path = r"D:\agent\agent\planner_audit_logs\planner_audit_20260616_202717.jsonl"
events = []
with open(path, encoding="utf-8") as f:
    for line in f:
        if line.strip():
            events.append(json.loads(line))

def get_action(e):
    hi = e.get("history_item") or {}
    return hi.get("action") or {}

def get_obs(e):
    hi = e.get("history_item") or {}
    return hi.get("observation") or {}

actions = [e for e in events if e.get("event_type") == "action_executed"]
print("Total action_executed:", len(actions))

c = Counter()
for a in actions:
    tool = get_action(a).get("tool_name", "?")
    c[tool] += 1

print("\nTool counts:")
for t, n in c.most_common():
    print(f"  {t}: {n}")

print("\nStep timeline:")
for a in actions:
    step = a["step"]
    tool = get_action(a).get("tool_name", "?")
    obs = get_obs(a)
    summary = (obs.get("result_summary") or "")[:85]
    blocked = ""
    prev = obs.get("result_preview") or ""
    if "blocked" in prev and "true" in prev.lower():
        blocked = " [BLOCKED]"
    print(f"  {step:2d} {tool:35s}{blocked} | {summary}")

skill = [a for a in actions if get_action(a).get("tool_name") == "Skill.run"]
print(f"\nSkill.run: {len(skill)} at steps", [a["step"] for a in skill])

targeted = [a for a in actions if get_action(a).get("tool_name") == "JoernTool.run_targeted_scan"]
print(f"run_targeted_scan: {len(targeted)} attempts")
blocked_t = [a for a in targeted if "拒绝" in (get_obs(a).get("result_summary") or "")]
print(f"  blocked/rejected: {len(blocked_t)}")

expand = [a for a in actions if get_action(a).get("tool_name") == "JoernTool.expand_flow_context"]
print(f"expand_flow_context: {len(expand)} at steps", [a["step"] for a in expand])

read_file = [a for a in actions if get_action(a).get("tool_name") == "FileTool.read_file"]
print(f"FileTool.read_file: {len(read_file)} (steps {read_file[0]['step']}-{read_file[-1]['step']})")

pkcs7 = []
for a in read_file:
    s = (get_obs(a).get("result_summary") or "") + (get_obs(a).get("result_preview") or "")
    if "pkcs7.c" in s:
        pkcs7.append(a)
print(f"\npkcs7.c FileTool.read_file: {len(pkcs7)} times")
for a in pkcs7:
    prev = get_obs(a).get("result_preview") or ""
    dup = '"skipped_duplicate": true' in prev or '"skipped_duplicate":true' in prev
    args = get_action(a).get("arguments") or {}
    print(f"  step {a['step']}: lines {args.get('start_line')}-{args.get('end_line')} {'[DUP]' if dup else ''}")

plans = [e for e in events if e.get("event_type") == "plan_generated"]
finish_plans = [p for p in plans if (p.get("planner_result") or {}).get("next_action", {}).get("tool_name") == "finish"]
print(f"\nfinish in plan_generated: {len(finish_plans)}")
finish_exec = [a for a in actions if get_action(a).get("tool_name") == "finish"]
print(f"finish executed: {len(finish_exec)}")

# Steps 4-6 detail
print("\nSteps 3-6 detail:")
for a in actions:
    if a["step"] in (3, 4, 5, 6):
        hi = a.get("history_item") or {}
        print(f"  step {a['step']}: tool={get_action(a).get('tool_name')} plan={hi.get('plan_summary','')[:100]}")

# After step 5 tool distribution
after5 = [a for a in actions if a["step"] >= 5]
c5 = Counter(get_action(a).get("tool_name") for a in after5)
print(f"\nFrom step 5 onward ({len(after5)} steps):")
for t, n in c5.most_common():
    print(f"  {t}: {n}")

run_fin = [e for e in events if e.get("event_type") == "run_finished"]
if run_fin:
    print(f"\nrun_finished: step={run_fin[-1].get('step')} reason={run_fin[-1].get('finish_reason')}")
