"""Planner 路径门控：完整索引缓存、索引拒绝 vs direct_fs 绕过。"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from planner import AgentPlannerExecutor
from project_file_index import build_project_file_index


class TestPlannerPathGate(unittest.TestCase):
    def _executor(self):
        return AgentPlannerExecutor(graph=MagicMock())

    def _java_tree(self, tmp: str) -> None:
        container = Path(tmp) / "src" / "main" / "java" / "org" / "example" / "container"
        container.mkdir(parents=True)
        (container / "WebSecurityConfig.java").write_text(
            "public class WebSecurityConfig {}\n", encoding="utf-8"
        )
        (Path(tmp) / ".editorconfig").write_text("root = true\n", encoding="utf-8")

    def _state(self, tmp: str):
        state = MagicMock()
        state.local_source_path = tmp
        state.language = "java"
        state.project_path = "/app/vuln_app"
        state.metadata = {}
        return state

    def test_live_index_has_full_paths_not_metadata_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._java_tree(tmp)
            executor = self._executor()
            state = self._state(tmp)
            executor._rebuild_project_file_index(state)

            live = executor._get_file_index(state)
            self.assertIsNotNone(live)
            self.assertEqual(len(live.all_paths), 2)
            sample = state.metadata["project_file_index"]["all_paths_sample"]
            self.assertLessEqual(len(sample), 120)
            self.assertIn("src/main/java/org/example/container/WebSecurityConfig.java", live.all_paths)

    def test_rejects_guessed_wrong_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._java_tree(tmp)
            executor = self._executor()
            state = self._state(tmp)
            executor._rebuild_project_file_index(state)

            resolved = executor._resolve_planner_read_path(
                state,
                "src/main/java/org/example/config/NonexistentConfig.java",
            )
            self.assertIsNone(resolved)

    def test_wrong_dir_same_basename_resolves_to_index_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._java_tree(tmp)
            executor = self._executor()
            state = self._state(tmp)
            executor._rebuild_project_file_index(state)

            resolved = executor._resolve_planner_read_path(
                state,
                "config/WebSecurityConfig.java",
            )
            self.assertIsNotNone(resolved)
            self.assertIn("container", resolved["path"])
            self.assertEqual(resolved["resolved_via"], "basename")

    def test_resolves_by_basename(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._java_tree(tmp)
            executor = self._executor()
            state = self._state(tmp)
            executor._rebuild_project_file_index(state)

            resolved = executor._resolve_planner_read_path(
                state, "WebSecurityConfig.java"
            )
            self.assertIsNotNone(resolved)
            self.assertIn("container", resolved["path"])
            self.assertEqual(resolved["resolved_via"], "basename")

    def test_no_direct_fs_bypass_for_unindexed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._java_tree(tmp)
            orphan = Path(tmp) / "orphan" / "Secret.java"
            orphan.parent.mkdir()
            orphan.write_text("class Secret {}\n", encoding="utf-8")

            executor = self._executor()
            state = self._state(tmp)
            executor._rebuild_project_file_index(state)

            rel = "orphan/Secret.java"
            self.assertTrue(os.path.isfile(Path(tmp) / rel))
            resolved = executor._resolve_planner_read_path(state, rel)
            self.assertIsNotNone(resolved)

            index = build_project_file_index(tmp, "java")
            index.all_paths.discard(rel)
            executor._live_file_index = index
            resolved2 = executor._resolve_planner_read_path(state, rel)
            self.assertIsNone(resolved2)

    def test_forced_l2_skips_index_rejected_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._java_tree(tmp)
            executor = self._executor()
            state = self._state(tmp)
            executor._rebuild_project_file_index(state)
            state.metadata["pending_l2_reads"] = [
                {
                    "flow_id": "f-1",
                    "path": "src/main/java/org/example/config/NonexistentConfig.java",
                    "kind": "config",
                }
            ]
            executor._is_l2_path_already_read = MagicMock(return_value=False)
            executor._mark_l2_path_as_read = MagicMock()
            executor._build_expand_flow_action = MagicMock(return_value=None)

            action = executor._build_forced_l2_read_action(state)
            self.assertIsNone(action)
            executor._mark_l2_path_as_read.assert_called()


if __name__ == "__main__":
    unittest.main()
