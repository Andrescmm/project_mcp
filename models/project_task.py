from markupsafe import Markup, escape
from odoo import fields, models

MCP_FIELD_GROUPS = "project_mcp.group_project_mcp_user,project.group_project_manager"


class ProjectTask(models.Model):
    _inherit = "project.task"

    ai_status = fields.Selection(
        [
            ("pending", "Pending"),
            ("in_progress", "In progress"),
            ("completed", "Completed"),
            ("changes_requested", "Changes requested"),
            ("verified", "Verified"),
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

    def _mcp_start(self, *, agent, branch=None):
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
        if mark_done:
            values["state"] = "1_done"
        self.write(values)
        self._mcp_post_note("MCP: implementation completed", summary)

    def _mcp_verify(self, *, result, notes, agent=None, update_task_state=True):
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
        if update_task_state:
            values["state"] = "1_done" if passed else "02_changes_requested"
        self.write(values)
        label = "passed" if passed else "failed"
        self._mcp_post_note(f"MCP: verification {label}", notes)
