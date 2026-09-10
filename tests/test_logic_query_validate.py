import unittest

import queries
from logic_query_validate import (
    is_joern_query_failure,
    validate_all_java_logic_queries,
    validate_all_registered_queries,
    validate_logic_query_source,
)


class LogicQueryValidateTest(unittest.TestCase):
    def test_is_joern_query_failure_detects_syntax(self):
        self.assertTrue(is_joern_query_failure("Error: invalid escape character at line 5"))
        self.assertTrue(is_joern_query_failure(""))
        self.assertFalse(is_joern_query_failure('val res: List[String] = List("IDOR | x")'))

    def test_all_java_logic_queries_static_pass(self):
        issues = validate_all_java_logic_queries(queries.java_logic_queries)
        self.assertEqual(
            issues, [],
            "java_logic_queries 静态校验失败:\n" + "\n".join(issues),
        )

    def test_all_registered_query_dicts_static_pass(self):
        issues = validate_all_registered_queries(
            queries.ALL_LOGIC_QUERY_REGISTRIES,
            queries.ALL_TAINT_QUERY_REGISTRIES,
        )
        self.assertEqual(
            issues, [],
            "queries.py 登记的全部 query 字典静态校验失败:\n" + "\n".join(issues),
        )

    def test_no_method_filter_code_in_java_logic_queries(self):
        for qname, src in queries.java_logic_queries.items():
            self.assertNotIn(
                ".filter(_.code(",
                src,
                f"{qname} 仍使用 .filter(_.code(...)",
            )
            self.assertNotIn(
                ".filterNot(_.code(",
                src,
                f"{qname} 仍使用 .filterNot(_.code(...)",
            )

    def test_auth_weakness_uses_where_not_filter(self):
        src = queries.java_logic_queries["auth_weakness"]
        self.assertIn(".where(_.name", src)
        self.assertNotIn(".filter(_.name", src)

    def test_csrf_gap_no_unused_val(self):
        src = queries.java_logic_queries["csrf_gap"]
        self.assertNotIn("globalCsrfOff", src)
        self.assertIn("CSRF_GAP", src)

    def test_idor_profile_no_invalid_scala_escape(self):
        src = queries.java_logic_queries["idor_profile"]
        self.assertNotIn("getUser\\(", src)
        issues = validate_logic_query_source("idor_profile", src)
        self.assertEqual(
            [i for i in issues if "非法" in i],
            [],
            issues,
        )

    def test_info_leak_response_no_invalid_scala_escape(self):
        src = queries.java_logic_queries["info_leak_response"]
        issues = validate_logic_query_source("info_leak_response", src)
        self.assertEqual(
            [i for i in issues if "非法" in i],
            [],
            issues,
        )

    def test_workflow_bypass_uses_where_on_method_code(self):
        src = queries.java_logic_queries["workflow_bypass"]
        self.assertIn(".where(_.code", src)
        self.assertNotIn(".filter(_.code", src)

    def test_business_logic_risk_uses_where_on_method_code(self):
        src = queries.java_logic_queries["business_logic_risk"]
        self.assertIn(".where(_.code", src)
        self.assertNotIn(".filter(_.code", src)

    def test_security_filter_chain_uses_split_queries(self):
        src = queries.java_logic_queries["security_filter_chain"]
        self.assertIn("filterChainBeans", src)
        self.assertIn("authorizeHttpRequests", src)
        # 5.x 遗留 API，避免只覆盖 Spring Security 6
        self.assertIn("authorizeRequests", src)
        self.assertIn("antMatchers", src)
        self.assertIn("legacyConfigurer", src)
        # 不得写死具体项目/产品（框架类型名 WebSecurityConfigurerAdapter 允许）
        self.assertNotIn("webgoat", src.lower())
        self.assertNotIn("webwolf", src.lower())
        self.assertNotIn("owasp", src.lower())
        issues = validate_logic_query_source("security_filter_chain", src)
        self.assertEqual(
            [i for i in issues if "非法" in i],
            [],
            issues,
        )

    def test_shiro_queries_no_invalid_scala_dot_escape(self):
        for qname in ("shiro_auth_guards", "shiro_security_config"):
            src = queries.java_logic_queries[qname]
            issues = validate_logic_query_source(qname, src)
            self.assertEqual(
                [i for i in issues if "非法" in i],
                [],
                issues,
            )

    def test_shiro_and_jaxrs_queries_present_in_java_and_generic(self):
        for key in (
            "shiro_auth_guards",
            "shiro_security_config",
            "jaxrs_auth_guards",
            "jaxrs_unprotected_resources",
        ):
            self.assertIn(key, queries.java_logic_queries, key)
            self.assertIn(key, queries.generic_logic_queries, key)
        shiro = queries.java_logic_queries["shiro_auth_guards"]
        self.assertIn("RequiresPermissions", shiro)
        self.assertIn("SecurityUtils", shiro)
        jaxrs = queries.java_logic_queries["jaxrs_auth_guards"]
        self.assertIn("RolesAllowed", jaxrs)
        self.assertIn("PermitAll", jaxrs)

    def test_auth_guards_param_identity_uses_parameter_annotation_traversal(self):
        src = queries.java_logic_queries["auth_guards"]
        self.assertIn("PARAM_IDENTITY_GUARD", src)
        self.assertIn("CurrentUser", src)
        self.assertIn(".parameter.annotation.name", src)
        self.assertNotIn(".parameter.exists", src)
        issues = validate_logic_query_source("auth_guards", src)
        self.assertEqual(
            [i for i in issues if "Type Mismatch" in i or "非法" in i],
            [],
            issues,
        )

    def test_csrf_and_auth_weakness_use_filter_not_where_not_on_call(self):
        for qname in ("csrf_gap", "auth_weakness"):
            src = queries.java_logic_queries[qname]
            self.assertNotIn(".whereNot(_.call.", src)
            self.assertIn(".filterNot(_.call.", src)
            issues = validate_logic_query_source(qname, src)
            self.assertEqual(
                [i for i in issues if "Type Mismatch" in i],
                [],
                issues,
            )


if __name__ == "__main__":
    unittest.main()
