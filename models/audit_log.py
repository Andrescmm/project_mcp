from datetime import timedelta

from odoo import api, fields, models


class ProjectMCPAuditLog(models.Model):
    _name = "project.mcp.audit.log"
    _description = "Project MCP Audit Log"
    _order = "create_date desc, id desc"
    _rec_name = "request_id"

    request_id = fields.Char(required=True, index=True, readonly=True)
    action = fields.Char(required=True, index=True, readonly=True)
    outcome = fields.Selection(
        [("success", "Success"), ("error", "Error")],
        required=True,
        index=True,
        readonly=True,
    )
    http_status = fields.Integer(required=True, readonly=True)
    user_id = fields.Many2one("res.users", readonly=True, ondelete="set null")
    actor_identifier = fields.Char(readonly=True, index=True)
    actor_name = fields.Char(readonly=True)
    project_id = fields.Many2one("project.project", readonly=True, ondelete="set null")
    task_id = fields.Many2one("project.task", readonly=True, ondelete="set null")
    source_ip = fields.Char(readonly=True)
    user_agent = fields.Char(readonly=True)
    details = fields.Json(readonly=True)

    @api.autovacuum
    def _gc_project_mcp_audit_logs(self):
        raw_retention = (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param("project_mcp.audit_retention_days", "90")
        )
        try:
            retention_days = max(1, min(int(raw_retention), 3650))
        except (TypeError, ValueError):
            retention_days = 90
        cutoff = fields.Datetime.now() - timedelta(days=retention_days)
        old_logs = self.sudo().search([("create_date", "<", cutoff)], limit=10000)
        old_logs.unlink()

    def init(self):
        super().init()
        self.env.cr.execute(
            "CREATE INDEX IF NOT EXISTS project_mcp_audit_log_create_date_idx "
            "ON project_mcp_audit_log (create_date)"
        )
