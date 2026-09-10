#!/usr/bin/env python3
"""Migrate pipeline JSON templates to YAML format in skills/pipelines/."""
import json
import os

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")
TEMPLATES_DIR = os.path.join(SKILLS_DIR, "templates")
EXPERT_DIR = os.path.join(TEMPLATES_DIR, "expert")
PIPELINES_DIR = os.path.join(SKILLS_DIR, "pipelines")

os.makedirs(PIPELINES_DIR, exist_ok=True)


def yaml_str(val, indent=0):
    """Simple YAML serializer for pipeline JSON values."""
    prefix = "  " * indent
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        # Check if needs quoting
        if any(c in val for c in ":{}[]#&*!|>'\",@`") or val.startswith((" ", "-")):
            escaped = val.replace("'", "''")
            return f"'{escaped}'"
        if val in ("true", "false", "null", "yes", "no", "on", "off"):
            return f"'{val}'"
        return val
    if isinstance(val, list):
        if not val:
            return "[]"
        if all(isinstance(v, str) for v in val):
            return "[" + ", ".join(yaml_str(v) for v in val) + "]"
        lines = []
        for item in val:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    if first:
                        lines.append(f"{prefix}- {k}: {yaml_str(v, indent+1)}")
                        first = False
                    else:
                        lines.append(f"{prefix}  {k}: {yaml_str(v, indent+1)}")
            else:
                lines.append(f"{prefix}- {yaml_str(item, indent+1)}")
        return "\n" + "\n".join(lines)
    if isinstance(val, dict):
        if not val:
            return "{}"
        lines = []
        for k, v in val.items():
            lines.append(f"{prefix}{k}: {yaml_str(v, indent+1)}")
        return "\n" + "\n".join(lines)
    return str(val)


def convert_pipeline(data):
    """Convert pipeline JSON dict to YAML string."""
    lines = []
    lines.append(f"# Pipeline: {data.get('skill_id', 'unknown')}")
    if data.get("name"):
        lines.append(f"# {data['name']}")
    lines.append("")

    # Top-level scalar fields
    for key in ("skill_id", "name", "summary", "min_score_to_activate",
                "start_node_id"):
        if key in data:
            lines.append(f"{key}: {yaml_str(data[key])}")

    # trigger_keywords
    if "trigger_keywords" in data:
        lines.append("trigger_keywords:")
        for kw in data["trigger_keywords"]:
            lines.append(f"  - {yaml_str(kw)}")

    # completion_hints
    if "completion_hints" in data:
        lines.append("completion_hints:")
        for hint in data["completion_hints"]:
            lines.append(f"  - {yaml_str(hint)}")

    # collab_skill_ids
    if "collab_skill_ids" in data:
        lines.append("collab_skill_ids:")
        for sid in data["collab_skill_ids"]:
            lines.append(f"  - {yaml_str(sid)}")

    # nodes
    if "nodes" in data:
        lines.append("")
        lines.append("nodes:")
        for node in data["nodes"]:
            lines.append(f"  - node_id: {yaml_str(node.get('node_id'))}")
            lines.append(f"    tool_name: {yaml_str(node.get('tool_name'))}")

            # arguments
            args = node.get("arguments")
            if args:
                lines.append("    arguments:")
                for k, v in args.items():
                    if isinstance(v, (dict, list)):
                        lines.append(f"      {k}: {yaml_str(v, 3)}")
                    else:
                        lines.append(f"      {k}: {yaml_str(v)}")

            # simple next pointers
            for key in ("success_next", "failure_next", "completion_signal"):
                if key in node:
                    lines.append(f"    {key}: {yaml_str(node[key])}")

            # parallel_actions
            if "parallel_actions" in node:
                lines.append("    parallel_actions:")
                for pa in node["parallel_actions"]:
                    lines.append(f"      - tool_name: {yaml_str(pa.get('tool_name'))}")
                    pa_args = pa.get("arguments")
                    if pa_args:
                        lines.append("        arguments:")
                        for k, v in pa_args.items():
                            lines.append(f"          {k}: {yaml_str(v)}")

            # expert_guidance
            eg = node.get("expert_guidance")
            if eg:
                lines.append("    expert_guidance:")
                for k, v in eg.items():
                    if isinstance(v, list):
                        lines.append(f"      {k}:")
                        for item in v:
                            lines.append(f"        - {yaml_str(item)}")
                    else:
                        lines.append(f"      {k}: {yaml_str(v)}")

            lines.append("")

    return "\n".join(lines)


def main():
    count = 0

    # Pipeline templates from templates/
    for fname in sorted(os.listdir(TEMPLATES_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(TEMPLATES_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        skill_id = data.get("skill_id", fname.replace(".json", ""))
        out_path = os.path.join(PIPELINES_DIR, f"{skill_id}.yaml")
        yaml_content = convert_pipeline(data)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(yaml_content + "\n")
        print(f"  OK: {fname} -> pipelines/{skill_id}.yaml")
        count += 1

    # Expert templates from templates/expert/
    for fname in sorted(os.listdir(EXPERT_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(EXPERT_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        skill_id = data.get("skill_id", fname.replace(".json", ""))
        out_path = os.path.join(PIPELINES_DIR, f"{skill_id}.yaml")
        yaml_content = convert_pipeline(data)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(yaml_content + "\n")
        print(f"  OK: expert/{fname} -> pipelines/{skill_id}.yaml")
        count += 1

    print(f"\nMigrated {count} pipeline templates to YAML")


if __name__ == "__main__":
    main()
