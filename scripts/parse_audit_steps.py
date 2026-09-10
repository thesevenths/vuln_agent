import re
import json
from collections import Counter

path = r"D:\agent\agent\planner_audit_logs\planner_audit_20260616_202717.html"
text = open(path, encoding="utf-8").read()

steps = []
for m in re.finditer(
    r"<section class='event'><h2>action_executed \(step (\d+).*?</h2>.*?<pre>(.*?)</pre>",
    text,
    re.DOTALL,
):
    step = int(m.group(1))
    block = m.group(2)
    block = block.replace("&quot;", '"').replace("&#x27;", "'").replace("&gt;", ">").replace("&lt;", "<")
    try:
        data = json.loads(block)
    except json.JSONDecodeError:
        continue
    action = data.get("action") or data.get("next_action") or {}
    tool = action.get("tool_name") or data.get("tool_name", "?")
    summary = data.get("result_summary", "")
    preview = data.get("result_preview", "")
    steps.append({"step": step, "tool": tool, "summary": summary, "preview": preview})

print("Total action_executed:", len(steps))
if steps:
    print("Steps range:", steps[0]["step"], "-", steps[-1]["step"])

c = Counter(s["tool"] for s in steps)
print("\nTool counts:")
for t, n in c.most_common():
    print(f"  {t}: {n}")

print("\nAll steps:")
for s in steps:
    sm = s["summary"][:90].replace("\n", " ")
    print(f"  step {s['step']:2d}: {s['tool']:35s} | {sm}")

skill_steps = [s for s in steps if s["tool"] == "Skill.run"]
print("\nSkill.run count:", len(skill_steps))
for s in skill_steps:
    print(f"  step {s['step']}: {s['summary'][:150]}")

pkcs7 = [s for s in steps if "pkcs7.c" in s["summary"] or "pkcs7.c" in s["preview"]]
print(f"\npkcs7.c mentions in actions: {len(pkcs7)}")
dup = [s for s in steps if "skipped_duplicate" in s["preview"] and "true" in s["preview"].lower()]
print(f"skipped_duplicate=true in preview: {len(dup)}")

finish_like = [s for s in steps if "finish" in s["tool"].lower() or s["tool"] == "FileTool.write_report"]
print("finish/write_report actions:", finish_like)

# plan_generated tool choices step 4
for m in re.finditer(r"plan_generated \(step (\d+).*?<pre>(.*?)</pre>", text, re.DOTALL):
    step = int(m.group(1))
    if step <= 6:
        block = m.group(2).replace("&quot;", '"')
        try:
            data = json.loads(block)
            na = data.get("next_action") or {}
            print(f"\nplan step {step} next_action: {na.get('tool_name')} | {data.get('plan_summary','')[:100]}")
        except json.JSONDecodeError:
            pass
