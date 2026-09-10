from odoo.exceptions import AccessError, UserError
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
        cls.other_project = cls.env["project.project"].create(
            {"name": "MCP Other Project", "privacy_visibility": "employees"}
        )
        stage_model = cls.env["project.task.type"]
        cls.stage_todo = stage_model.create(
            {"name": "To Do", "sequence": 1, "project_ids": [(6, 0, [cls.project.id])]}
        )
        cls.stage_review = stage_model.create(
            {"name": "In Review", "sequence": 2, "project_ids": [(6, 0, [cls.project.id])]}
        )
        cls.foreign_stage = stage_model.create(
            {"name": "Backlog", "sequence": 1, "project_ids": [(6, 0, [cls.other_project.id])]}
        )
        cls.task = cls.env["project.task"].create(
            {
                "name": "Implement lot controls",
                "project_id": cls.project.id,
                "stage_id": cls.stage_todo.id,
            }
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

    def test_delivery_metadata_is_recorded(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_start(
            agent="claude-code",
            branch="feat/lots",
            repository="git@github.com:example/repo.git",
        )
        task._mcp_complete(
            summary="Implemented",
            test_results="12 tests passed",
            pull_request_url="https://github.com/example/repo/pull/7",
            deployment_environment="staging",
            mark_done=False,
        )
        task._mcp_verify(
            result="passed",
            notes="Reviewed",
            evidence="CI run 123 passed",
            update_task_state=False,
        )
        self.assertEqual(task.git_repository, "git@github.com:example/repo.git")
        self.assertEqual(task.test_results, "12 tests passed")
        self.assertEqual(task.pull_request_url, "https://github.com/example/repo/pull/7")
        self.assertEqual(task.deployment_environment, "staging")
        self.assertEqual(task.verification_evidence, "CI run 123 passed")

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

    def test_update_renames_and_edits_task_fields(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_update(
            {
                "name": "Implement lot traceability",
                "description": "<p>New scope</p>",
                "priority": "1",
                "allocated_hours": 4.0,
            },
            note="Renamed after refinement.",
        )
        self.assertEqual(task.name, "Implement lot traceability")
        self.assertEqual(task.priority, "1")
        self.assertEqual(task.allocated_hours, 4.0)
        self.assertIn("New scope", task.description)
        self.assertIn("Renamed after refinement.", task.message_ids[0].body)

    def test_update_without_values_is_rejected(self):
        with self.assertRaises(UserError):
            self.task.with_user(self.mcp_user)._mcp_update({})

    def test_move_stage_by_name_and_by_id(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_move_stage(stage_name="in review")
        self.assertEqual(task.stage_id, self.stage_review)
        task._mcp_move_stage(stage_id=self.stage_todo.id)
        self.assertEqual(task.stage_id, self.stage_todo)

    def test_move_stage_rejects_unknown_or_foreign_stage(self):
        task = self.task.with_user(self.mcp_user)
        with self.assertRaises(UserError):
            task._mcp_move_stage(stage_name="Does not exist")
        with self.assertRaises(UserError):
            task._mcp_move_stage(stage_id=self.foreign_stage.id)

    def test_set_state(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_set_state("03_approved")
        self.assertEqual(task.state, "03_approved")
        with self.assertRaises(UserError):
            task._mcp_set_state("not_a_state")

    def test_assignees_set_add_and_remove(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_set_assignees(self.mcp_user, mode="set")
        self.assertEqual(task.user_ids, self.mcp_user)
        task._mcp_set_assignees(self.read_only_user, mode="add")
        self.assertEqual(task.user_ids, self.mcp_user | self.read_only_user)
        task._mcp_set_assignees(self.mcp_user, mode="remove")
        self.assertEqual(task.user_ids, self.read_only_user)
        task._mcp_set_assignees(self.env["res.users"], mode="set")
        self.assertFalse(task.user_ids)
        with self.assertRaises(UserError):
            task._mcp_set_assignees(self.mcp_user, mode="replace")

    def test_archive_and_restore(self):
        task = self.task.with_user(self.mcp_user)
        task._mcp_set_active(False)
        self.assertFalse(task.active)
        task._mcp_set_active(True)
        self.assertTrue(task.active)

    def test_dependencies_are_same_project_and_non_recursive(self):
        blocker = self.env["project.task"].create(
            {"name": "Prepare schema", "project_id": self.project.id}
        )
        foreign = self.env["project.task"].create(
            {"name": "Foreign task", "project_id": self.other_project.id}
        )
        task = self.task.with_user(self.mcp_user)
        task._mcp_set_dependencies(blocker.with_user(self.mcp_user), mode="set")
        self.assertEqual(task.depend_on_ids, blocker)
        task._mcp_set_dependencies(blocker.with_user(self.mcp_user), mode="remove")
        self.assertFalse(task.depend_on_ids)
        with self.assertRaises(UserError):
            task._mcp_set_dependencies(task, mode="add")
        with self.assertRaises(UserError):
            task._mcp_set_dependencies(foreign.with_user(self.mcp_user), mode="add")

    def test_create_task_logs_the_agent(self):
        task = (
            self.env["project.task"]
            .with_user(self.mcp_user)
            ._mcp_create_task(
                {"name": "Write migration script", "project_id": self.project.id},
                agent="claude-code",
            )
        )
        self.assertEqual(task.project_id, self.project)
        self.assertIn("claude-code", task.message_ids[0].body)
