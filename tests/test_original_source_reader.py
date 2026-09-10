"""Quick smoke test for _read_original_source and related methods."""
import sys, os, tempfile
sys.path.insert(0, ".")
from joern_vuln_scanner import JoernVulnScannerHTTP

# Create a temp Java file to test with
td = tempfile.mkdtemp()
sub = os.path.join(td, "com", "example")
os.makedirs(sub)
fp = os.path.join(sub, "UserController.java")
with open(fp, "w", encoding="utf-8") as fh:
    fh.write(
        "package com.example;\n"
        "\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "\n"
        "/**\n"
        " * User management controller.\n"
        " */\n"
        "@RestController\n"
        "@RequestMapping(\"/api/users\")\n"
        "public class UserController {\n"
        "\n"
        "    @GetMapping\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "    public List<User> listUsers() {\n"
        "        return userService.findAll();\n"
        "    }\n"
        "\n"
        "    @DeleteMapping(\"/{id}\")\n"
        "    public void deleteUser(@PathVariable Long id) {\n"
        "        userService.delete(id);\n"
        "    }\n"
        "}\n"
    )

s = JoernVulnScannerHTTP.__new__(JoernVulnScannerHTTP)
s.local_source_path = td
s.local_roots = [td]

# Test: read original source around line 19 (deleteUser) with window=10
cand = {"file": os.path.join("com", "example", "UserController.java"), "line": 19}
result = s._read_original_source(cand, window=10)
print("=== _read_original_source result ===")
print(result)
print()

assert result, "Expected non-empty result"
assert "Original source" in result, "Missing header"
assert "@DeleteMapping" in result, "Missing @DeleteMapping annotation"
assert "@PreAuthorize" in result, "Missing @PreAuthorize from adjacent method"
print("PASS: original source preserves annotations and spatial relationships")

# Test: default window=60 should capture class-level comment too
result60 = s._read_original_source(cand)  # default window=60
assert "User management controller" in result60, "Default window should capture class comment"
print("PASS: default window=60 captures class-level comment (spatial relationship)")

# Test: empty file field
r2 = s._read_original_source({"file": "", "line": 5})
assert r2 == "", "Expected empty for empty file"
print("PASS: empty file returns empty")

# Test: no line number
r3 = s._read_original_source({"file": os.path.join("com", "example", "UserController.java")})
assert r3, "Expected non-empty even without line number"
assert "first 200 lines" in r3, "Expected first-200-lines header"
print("PASS: no line number returns first 200 lines")

# Test: _logic_scan_language_ext
s._current_logic_framework = "spring"
assert s._logic_scan_language_ext() == "java"
s._current_logic_framework = "python"
assert s._logic_scan_language_ext() == "python"
s._current_logic_framework = "go"
assert s._logic_scan_language_ext() == "go"
print("PASS: _logic_scan_language_ext returns correct extensions")

# Cleanup
import shutil
shutil.rmtree(td, ignore_errors=True)
print("\n=== ALL TESTS PASSED ===")
