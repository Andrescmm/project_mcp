from markupsafe import Markup, escape
from odoo import Command, _, api, fields, models
from odoo.exceptions import UserError
from odoo.tools import html2plaintext

MCP_FIELD_GROUPS = "project_mcp.group_project_mcp_user,project.group_project_manager"
MCP_ASSIGNEE_MODES = ("set", "add", "remove")


class ProjectTask(models.Model):
    _inherit = "project.task"

    ai_status = fields.Selection(
        [
            ("pending", "Pending"),
            ("in_progress", "In progress"),
            ("completed", "Completed"),
            ("changes_requested", "Changes requested"),
            ("verified", "Verified"),
            ("cancelled", "Cancelled"),
        ],
        string="AI status",
        default="pending",
        copy=False,
        tracking=True,
        index=True,
        groups=MCP_FIELD_GROUPS,
    )
    ai_agent = fields.Char(
        string="AI agent", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    git_branch = fields.Char(
        string="Git branch", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    git_commit = fields.Char(
        string="Git commit", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    ai_summary = fields.Text(
        string="AI summary", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    verification_status = fields.Selection(
        [
            ("pending", "Pending"),
            ("passed", "Passed"),
            ("failed", "Failed"),
        ],
        string="Verification",
        default="pending",
        copy=False,
        tracking=True,
        index=True,
        groups=MCP_FIELD_GROUPS,
    )
    verification_notes = fields.Text(copy=False, tracking=True, groups=MCP_FIELD_GROUPS)
    acceptance_criteria = fields.Text(
        string="Acceptance criteria", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    test_results = fields.Text(
        string="Test results", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    git_repository = fields.Char(
        string="Git repository", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    pull_request_url = fields.Char(
        string="Pull request URL", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    deployment_environment = fields.Char(
        string="Deployment environment", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    verification_evidence = fields.Text(
        string="Verification evidence", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    ai_blockers = fields.Text(
        string="AI blockers", copy=False, tracking=True, groups=MCP_FIELD_GROUPS
    )
    ai_started_at = fields.Datetime(copy=False, readonly=True, groups=MCP_FIELD_GROUPS)
    ai_completed_at = fields.Datetime(copy=False, readonly=True, groups=MCP_FIELD_GROUPS)
    ai_verified_at = fields.Datetime(copy=False, readonly=True, groups=MCP_FIELD_GROUPS)

    def _mcp_check_write_access(self):
        self.check_access_rights("write")
        self.check_access_rule("write")

    def _mcp_post_note(self, title, text):
        safe_title = escape(title)
        safe_text = escape(text or "").replace("\n", Markup("<br>"))
        self.message_post(
            body=Markup("<p><strong>%s</strong></p><p>%s</p>") % (safe_title, safe_text),
            message_type="comment",
            subtype_xmlid="mail.mt_note",
        )

    def _mcp_start(self, *, agent, branch=None, repository=None):
        self.ensure_one()
        self._mcp_check_write_access()
        values = {
            "ai_status": "in_progress",
            "ai_agent": agent,
            "ai_started_at": fields.Datetime.now(),
            "ai_completed_at": False,
            "ai_verified_at": False,
            "verification_status": "pending",
            "verification_notes": False,
            "state": "01_in_progress",
        }
        if branch:
            values["git_branch"] = branch
        if repository:
            values["git_repository"] = repository
        self.write(values)
        self._mcp_post_note("MCP: task started", f"Agent: {agent}")

    def _mcp_add_comment(self, comment):
        self.ensure_one()
        self._mcp_check_write_access()
        self._mcp_post_note("MCP agent comment", comment)

    def _mcp_complete(
        self,
        *,
        summary,
        agent=None,
        branch=None,
        commit=None,
        test_results=None,
        pull_request_url=None,
        deployment_environment=None,
        mark_done=True,
    ):
        self.ensure_one()
        self._mcp_check_write_access()
        values = {
            "ai_status": "completed",
            "ai_summary": summary,
            "ai_completed_at": fields.Datetime.now(),
            "verification_status": "pending",
            "verification_notes": False,
            "ai_verified_at": False,
        }
        if agent:
            values["ai_agent"] = agent
        if branch:
            values["git_branch"] = branch
        if commit:
            values["git_commit"] = commit
        if test_results:
            values["test_results"] = test_results
        if pull_request_url:
            values["pull_request_url"] = pull_request_url
        if deployment_environment:
            values["deployment_environment"] = deployment_environment
        if mark_done:
            values["state"] = "1_done"
        self.write(values)
        self._mcp_post_note("MCP: implementation completed", summary)

    def _mcp_verify(
        self, *, result, notes, agent=None, evidence=None, update_task_state=True
    ):
        self.ensure_one()
        self._mcp_check_write_access()
        passed = result == "passed"
        values = {
            "ai_status": "verified" if passed else "changes_requested",
            "verification_status": result,
            "verification_notes": notes,
            "ai_verified_at": fields.Datetime.now(),
        }
        if agent:
            values["ai_agent"] = agent
        if evidence:
            values["verification_evidence"] = evidence
        if update_task_state:
            values["state"] = "1_done" if passed else "02_changes_requested"
        self.write(values)
        label = "passed" if passed else "failed"
        self._mcp_post_note(f"MCP: verification {label}", notes)

    # ------------------------------------------------------------------
    # Generic task management helpers used by the MCP REST API
    # ------------------------------------------------------------------
    def _mcp_value_label(self, field_name):
        """Human readable representation of a field value, used in chatter notes."""
        self.ensure_one()
        field = self._fields[field_name]
        value = self[field_name]
        if field.type in ("many2one", "many2many", "one2many"):
            return ", ".join(value.mapped("display_name")) or "-"
        if field.type == "selection":
            return dict(field._description_selection(self.env)).get(value) or "-"
        if field.type in ("date", "datetime"):
            return fields.Datetime.to_string(value) if value else "-"
        if field.type == "html":
            text = " ".join(html2plaintext(value or "").split())
            return (text[:120] + "...") if len(text) > 120 else (text or "-")
        if field.type == "boolean":
            return "yes" if value else "no"
        return str(value) if value not in (False, None, "") else "-"

    def _mcp_write_and_log(self, values, *, title, extra_note=None):
        """Write ``values`` and post a chatter note describing what changed."""
        self.ensure_one()
        self._mcp_check_write_access()
        if not values:
            raise UserError(_("No supported field was provided to update."))
        # project.task.write() may add its own keys to the dict, so keep our own list.
        field_names = list(values)
        before = {name: self._mcp_value_label(name) for name in field_names}
        self.write(values)
        lines = []
        for name in field_names:
            after = self._mcp_value_label(name)
            if after != before[name]:
                label = self._fields[name].string or name
                lines.append(f"{label}: {before[name]} -> {after}")
        if extra_note:
            lines.append(extra_note)
        self._mcp_post_note(title, "\n".join(lines) or _("No effective change."))
        return self

    def _mcp_update(self, values, *, note=None):
        """Update editable task fields (name, description, priority, deadline...)."""
        return self._mcp_write_and_log(values, title="MCP: task updated", extra_note=note)

    def _mcp_find_stage(self, *, stage_id=None, stage_name=None):
        """Return the stage of the task project matching ``stage_id`` or ``stage_name``."""
        self.ensure_one()
        if not self.project_id:
            raise UserError(_("Task %s has no project, so it has no stages.", self.id))
        stage_model = self.env["project.task.type"]
        domain = [("project_ids", "=", self.project_id.id)]
        if stage_id:
            stage = stage_model.search(domain + [("id", "=", stage_id)], limit=1)
            if not stage:
                raise UserError(
                    _(
                        "Stage %(stage)s is not available in project %(project)s.",
                        stage=stage_id,
                        project=self.project_id.display_name,
                    )
                )
            return stage
        if not stage_name:
            raise UserError(_("A stage id or a stage name is required."))
        matches = stage_model.search(
            domain + [("name", "=ilike", stage_name)], order="sequence, id"
        ) or stage_model.search(domain + [("name", "ilike", stage_name)], order="sequence, id")
        if not matches:
            raise UserError(
                _(
                    "No stage named '%(name)s' in project %(project)s.",
                    name=stage_name,
                    project=self.project_id.display_name,
                )
            )
        if len(matches) > 1:
            raise UserError(
                _(
                    "'%(name)s' matches several stages: %(stages)s.",
                    name=stage_name,
                    stages=", ".join(matches.mapped("name")),
                )
            )
        return matches

    def _mcp_move_stage(self, *, stage_id=None, stage_name=None, note=None):
        """Move the task to another stage of its own project."""
        self.ensure_one()
        self._mcp_check_write_access()
        stage = self._mcp_find_stage(stage_id=stage_id, stage_name=stage_name)
        return self._mcp_write_and_log(
            {"stage_id": stage.id}, title="MCP: stage changed", extra_note=note
        )

    def _mcp_set_state(self, state, *, note=None):
        """Set the task state (in progress, done, cancelled...)."""
        self.ensure_one()
        if state not in self._fields["state"].get_values(self.env):
            raise UserError(_("Unknown task state '%s'.", state))
        values = {"state": state}
        if state == "01_in_progress":
            values.update(
                {
                    "ai_status": "in_progress",
                    "verification_status": "pending",
                    "verification_notes": False,
                    "ai_verified_at": False,
                }
            )
        elif state == "1_canceled":
            values["ai_status"] = "cancelled"
        return self._mcp_write_and_log(values, title="MCP: state changed", extra_note=note)

    def _mcp_set_assignees(self, users, *, mode="set", note=None):
        """Replace, add or remove task assignees."""
        self.ensure_one()
        if mode not in MCP_ASSIGNEE_MODES:
            raise UserError(_("Unknown assignee mode '%s'.", mode))
        if mode == "set":
            command = [Command.set(users.ids)]
        elif mode == "add":
            command = [Command.link(user_id) for user_id in users.ids]
        else:
            command = [Command.unlink(user_id) for user_id in users.ids]
        return self._mcp_write_and_log(
            {"user_ids": command}, title="MCP: assignees changed", extra_note=note
        )

    def _mcp_set_dependencies(self, tasks, *, mode="set", note=None):
        """Replace, add or remove tasks that block this task."""
        self.ensure_one()
        if not self.allow_task_dependencies:
            raise UserError(_("Task dependencies are not enabled for this project."))
        if mode not in MCP_ASSIGNEE_MODES:
            raise UserError(_("Unknown dependency mode '%s'.", mode))
        if self in tasks:
            raise UserError(_("A task cannot depend on itself."))
        foreign_tasks = tasks.filtered(lambda task: task.project_id != self.project_id)
        if foreign_tasks:
            raise UserError(_("Dependencies must belong to the same project."))
        if mode == "set":
            command = [Command.set(tasks.ids)]
        elif mode == "add":
            command = [Command.link(task_id) for task_id in tasks.ids]
        else:
            command = [Command.unlink(task_id) for task_id in tasks.ids]
        return self._mcp_write_and_log(
            {"depend_on_ids": command},
            title="MCP: dependencies changed",
            extra_note=note,
        )

    def _mcp_set_active(self, active, *, note=None):
        """Archive or restore the task."""
        self.ensure_one()
        title = "MCP: task restored" if active else "MCP: task archived"
        return self._mcp_write_and_log({"active": active}, title=title, extra_note=note)

    @api.model
    def _mcp_create_task(self, values, *, agent=None):
        """Create a task through the MCP API and trace it in the chatter."""
        task = self.create(values)
        task._mcp_post_note(
            "MCP: task created",
            _("Created by agent: %s", agent) if agent else _("Created through the MCP API."),
        )
        return task
