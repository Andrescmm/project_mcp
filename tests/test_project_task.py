from odoo.exceptions import AccessError
from odoo.tests import tagged
from odoo.tests.common import TransactionCase, new_test_user


@tagged("post_install", "-at_install")
class TestProjectMCPTaskWorkflow(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.mcp_user = new_test_user(
            cls.env,
            login="project-mcp-test",
            groups="project_mcp.group_project_mcp_user",
        )
        cls.read_only_user = new_test_user(
            cls.env,
            login="project-mcp-read-only-test",
            groups="base.group_user",
        )
        cls.project = cls.env["project.project"].create(
            {"name": "MCP Test Project", "privacy_visibility": "employees"}
        )
        cls.task = cls.env["project.task"].create(
            {"name": "Implement lot controls", "project_id": cls.project.id}
        )

    def test_full_ai_workflow(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_start(agent="claude-code", branch="feat/lots")
        self.assertEqual(task.ai_status, "in_progress")
        self.assertEqual(task.state, "01_in_progress")
        self.assertTrue(task.ai_started_at)

        task._mcp_complete(
            summary="Implemented lot controls and tests.",
            agent="claude-code",
            branch="feat/lots",
            commit="abcdef1234567",
            mark_done=True,
        )
        self.assertEqual(task.ai_status, "completed")
        self.assertEqual(task.state, "1_done")
        self.assertEqual(task.git_commit, "abcdef1234567")

        task._mcp_verify(
            result="passed",
            notes="All acceptance checks passed.",
            agent="claude-code-reviewer",
            update_task_state=True,
        )
        self.assertEqual(task.ai_status, "verified")
        self.assertEqual(task.verification_status, "passed")
        self.assertEqual(task.state, "1_done")

    def test_failed_verification_requests_changes(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_verify(
            result="failed",
            notes="Missing regression test.",
            update_task_state=True,
        )
        self.assertEqual(task.ai_status, "changes_requested")
        self.assertEqual(task.verification_status, "failed")
        self.assertEqual(task.state, "02_changes_requested")

    def test_native_odoo_permissions_are_enforced(self):
        with self.assertRaises(AccessError):
            self.task.with_user(self.read_only_user)._mcp_start(agent="unauthorized")
