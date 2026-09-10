"""One-off parser for planner audit HTML stats."""
import re
import sys
from pathlib import Path


def unescape_html(s: str) -> str:
    return (
        s.replace("&quot;", '"')
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
    )


def main(path: str) -> None:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    cut = text.find("23:08:56")  # 2nd scan starts ~here
    first = unescape_html(text[:cut] if cut > 0 else text)

    sections = re.findall(r"## 漏洞类型: ([A-Z_]+)（共 (\d+) 条 flow）", first)
    total_flows = sum(int(n) for _, n in sections)
    print("=== first full scan (step 3 report) ===")
    print(f"vuln types: {len(sections)}")
    print(f"total flows analyzed: {total_flows}")
    for t, n in sections:
        print(f"  {t}: {n} flows")

    amb19 = re.search(r'"ambiguous_flows"\s*:\s*\[', first)
    if amb19:
        print("ambiguous_flows array present in first scan result")
    for m in re.finditer(r'"previous_verdict"\s*:\s*"([^"]{0,80})"', first):
        pass
    amb_list = re.findall(r'"vuln_type"\s*:\s*"([^"]+)".*?"flow_id"\s*:\s*"([^"]+)"', first[:2000000])
    print(f"ambiguous flow entries (rough): {len(amb_list)}")

    def verdict_stats(chunk: str, label: str) -> None:
        yes_pat = re.findall(r"是否真实漏洞\s*[：:]\s*✅\s*是", chunk)
        no_pat = re.findall(r"是否真实漏洞\s*[：:]\s*❌\s*否", chunk)
        partial_pat = re.findall(r"是否真实漏洞\s*[：:]\s*⚠️", chunk)
        amb_markers = sum(chunk.count(m) for m in _AMBIGUOUS_MARKERS)
        print(f"\n{label}:")
        print(f"  verdict YES (structured line): {len(yes_pat)}")
        print(f"  verdict NO (structured line): {len(no_pat)}")
        print(f"  verdict PARTIAL emoji: {len(partial_pat)}")
        print(f"  ambiguous marker hits in analysis text: {amb_markers}")

    _AMBIGUOUS_MARKERS = [
        "⚠️ 部分是",
        "待确认",
        "证据不足",
        "无法确定",
        "不确定",
        "可能是",
    ]
    verdict_stats(first, "first scan report (step 3)")
    verdict_stats(unescape_html(text), "full html (incl 2nd scan)")

    m19 = re.search(r'"ambiguous_flows"\s*:\s*\[', first)
    if m19:
        # count flow_id entries after first ambiguous_flows
        pos = first.find('"ambiguous_flows"')
        block = first[pos : pos + 120000]
        ids = re.findall(r'"flow_id"\s*:\s*"([^"]+)"', block)
        print(f"\nfirst scan ambiguous_flows entries: {len(ids)}")
        for fid in ids[:25]:
            print(f"  {fid}")
        if len(ids) > 25:
            print(f"  ... +{len(ids)-25} more")

    reads = len(re.findall(r"result_summary.*?已读取 .*ssl_test_common_source\.c", text))
    print(f"\nPlanner read_file(ssl_test_common_source.c) count: {reads}")

    print("\nread ranges (planner steps 4-12 region):")
    region = text[text.find("step 4"): text.find("step 13")] if "step 4" in text else text
    seen = []
    for m in re.finditer(r"ssl_test_common_source\.c", region):
        seg = region[m.start() : m.start() + 400]
        sl = re.search(r"start_line.*?(\d+)", seg)
        el = re.search(r"end_line.*?(\d+)", seg)
        if sl and el:
            r = (sl.group(1), el.group(1))
            if r not in seen:
                seen.append(r)
                print(f"  L{sl.group(1)}-L{el.group(1)}")

    amb = re.search(r"仍有 \*\*(\d+)\*\* 条 flow 结论模糊", text)
    if amb:
        print(f"\n最终仍模糊 flow: {amb.group(1)}")
        block = text[amb.start() : amb.start() + 3000]
        for line in re.findall(r"- \*\*([^*]+)\*\* `([^`]+)`: ([^\n]+)", block):
            print(f"  {line[0]} {line[1]} -> {line[2]}")

    inc = re.search(r"增量复核 (\d+) 条", text)
    if inc:
        print(f"\n2nd incremental review count: {inc.group(1)}")

    lfp_first = len(re.findall(r"likely_false_positive", first))
    lfp_all = len(re.findall(r"likely_false_positive", text))
    conf_first = len(re.findall(r'"verdict"\s*:\s*"confirmed"', first))
    print(f"\nscanner refutation verdict likely_false_positive: first={lfp_first}, all={lfp_all}")
    print(f"scanner refutation verdict confirmed: first={conf_first}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\15952\Downloads\planner_audit_20260610_210019.html")
