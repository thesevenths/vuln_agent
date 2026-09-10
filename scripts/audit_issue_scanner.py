"""Scan planner audit HTML for known issue patterns."""
import re
import sys
from collections import Counter
from pathlib import Path


def unescape(s: str) -> str:
    return (
        s.replace("&quot;", '"')
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
    )


def main(path: str) -> None:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    u = unescape(text)

    print("=== RUN META ===")
    m = re.search(r"开始时间.*?(\d{4}-\d{2}-\d{2}T[\d:.]+)", text)
    m2 = re.search(r"结束时间.*?(\d{4}-\d{2}-\d{2}T[\d:.]+)", text)
    print(f"start: {m.group(1) if m else '?'}")
    print(f"end:   {m2.group(1) if m2 else '?'}")

    steps = re.findall(r"<h2>plan_updated \(step (\d+)", text)
    print(f"planner steps (plan_updated): {max(int(s) for s in steps) if steps else 0}")

    print("\n=== CONTEXT / CONFIG ===")
  # initial snapshot wrong paths
    if "E:\\model-similarity" in text[:8000]:
        print("- run_started project_path/local_source_path = E:\\model-similarity (not mbedtls path)")
    lang_hits = Counter(re.findall(r'"language"\s*:\s*"([^"]+)"', text[:15000]))
    print(f"- language values early: {dict(lang_hits)}")

    print("\n=== SCANNER INTERNAL ===")
    print(f"- JoernProject in audit: {u.count('JoernProject')}")
    print(f"- no_method_seed: {u.count('no_method_seed')}")
    print(f"- backtrace_hops: 0 occurrences: {u.count('\"backtrace_hops\": 0')}")
    print(f"- context sufficient false: {u.count('\"sufficient\": false')}")
    print(f"- expansion_query_skipped_duplicate: {text.count('expansion_query_skipped_duplicate')}")
    print(f"- body.p in queries: {text.count('.body.p')}")
    print(f"- dumpRaw in queries: {text.count('dumpRaw')}")
    print(f"- ANSI escape \\u001b: {text.count(chr(27)) + text.count('\\\\u001b')}")
    print(f"- likely_false_positive: {text.count('likely_false_positive')}")
    print(f"- refutation_verdict confirmed: {text.count('\"verdict\": \"confirmed\"')}")
    print(f"- flow_quality_skipped: {text.count('flow_quality_skipped')}")

    print("\n=== VERDICTS ===")
    print(f"- structured YES: {len(re.findall(r'是否真实漏洞[：:]\\s*✅\\s*是', u))}")
    print(f"- structured NO: {len(re.findall(r'是否真实漏洞[：:]\\s*❌\\s*否', u))}")
    print(f"- structured PARTIAL: {len(re.findall(r'是否真实漏洞[：:]\\s*⚠️', u))}")

    print("\n=== PLANNER L2 ===")
    reads = re.findall(r"已读取 ([^<\"]+)", text)
    read_paths = [r.strip() for r in reads if "ssl_test" in r or "mbedtls" in r or "CMake" in r]
    print(f"- FileTool read_file summaries: {len(reads)}")
    c = Counter(read_paths)
    for p, n in c.most_common(8):
        print(f"  x{n}: {p[:80]}")

    print("\n=== PLANNER ISSUES ===")
    for pat, label in [
        (r"无法稳定解析规划结果", "planner parse fallback"),
        (r"拒绝 finish", "finish rejected"),
        (r"force_finished_scan_limit", "force finished scan limit"),
        (r"done=true.*finish", "finish attempts"),
    ]:
        print(f"- {label}: {len(re.findall(pat, text))}")

    print("\n=== INCREMENTAL / AMBIGUOUS ===")
    inc = re.search(r"增量复核 (\d+) 条", text)
    print(f"- incremental review: {inc.group(1) if inc else '?'}")
    amb = re.search(r"仍有 \*\*(\d+)\*\* 条 flow 结论模糊", u)
    print(f"- final ambiguous: {amb.group(1) if amb else '?'}")

    print("\n=== QUERY FAILURES ===")
    print(f"- transport failure / timeout hints: {text.count('JOERN_TRANSPORT') + text.count('timeout')}")
    print(f"- circuit breaker: {text.count('circuit_breaker')}")
    print(f"- checkpoint skip: {text.count('checkpoint')}")

    print("\n=== SUFFICIENCY / ITER ===")
    iters = re.findall(r'"iteration"\s*:\s*(\d+)', text)
    if iters:
        print(f"- max iteration seen: {max(int(x) for x in iters)}")

    # flows with inconclusive refutation but YES verdict
    blocks = re.findall(
        r"是否真实漏洞[：:]\s*✅\s*是[\s\S]{0,800}?refutation_verdict[`\s|:]*inconclusive",
        u,
    )
    print(f"- YES verdict + inconclusive refutation (near): {len(blocks)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\15952\Downloads\planner_audit_20260610_210019.html")
