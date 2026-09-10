import json
import unittest
from pathlib import Path

import queries
from cwe_query_registry import (
    CWE_PRIMARY_LOGIC_QUERIES,
    cwe_numbers_from_template_filename,
    iter_cwe_skill_template_paths,
    validate_cwe_primary_queries,
)
from joern_vuln_scanner import JoernVulnScannerHTTP


class CweQueryCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cwe_dir = Path(__file__).resolve().parent.parent / "skills" / "templates" / "cwe"
        cls.template_cwes: set = set()
        for path in iter_cwe_skill_template_paths(cls.cwe_dir):
            data = json.loads(path.read_text(encoding="utf-8"))
            for raw in data.get("source_cwe", []):
                cls.template_cwes.add(str(raw).replace("CWE-", "").strip())
            cls.template_cwes.update(cwe_numbers_from_template_filename(path.name))

    def test_every_template_cwe_has_primary_query_registry(self):
        missing = self.template_cwes - set(CWE_PRIMARY_LOGIC_QUERIES.keys())
        self.assertEqual(
            missing, set(),
            f"以下 CWE 模板未登记主查询: {sorted(missing)}",
        )

    def test_logic_cwe_map_covers_all_template_cwes(self):
        java_queries = set(queries.java_logic_queries.keys())
        errors = validate_cwe_primary_queries(
            JoernVulnScannerHTTP._LOGIC_CWE_QUERY_MAP,
            java_queries,
            template_cwes=self.template_cwes,
        )
        self.assertEqual(errors, [], "\n".join(errors))

    def test_fragment_files_excluded_from_template_cwes(self):
        stems = {
            p.stem.replace("cwe_", "")
            for p in iter_cwe_skill_template_paths(self.cwe_dir)
        }
        self.assertNotIn("logic_common", stems)
        self.assertNotIn("logic_common", self.template_cwes)
        tagged = set(JoernVulnScannerHTTP._LOGIC_QUERY_TAGS.keys())
        for qname in queries.java_logic_queries:
            if qname in ("endpoint_enumeration",):
                continue
            self.assertIn(
                qname, tagged,
                f"java_logic_queries['{qname}'] 缺少 _LOGIC_QUERY_TAGS 条目",
            )


if __name__ == "__main__":
    unittest.main()
