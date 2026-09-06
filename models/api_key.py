from odoo import _, fields, models
from odoo.addons.base.models.res_users import check_identity
from odoo.exceptions import AccessError


class ResUsers(models.Model):
    _inherit = "res.users"

    @check_identity
    def project_mcp_api_key_wizard(self):
        self.ensure_one()
        if self != self.env.user or not self.env.user.has_group(
            "project_mcp.group_project_mcp_user"
        ):
            raise AccessError(_("Only the signed-in Project MCP user can generate this key."))
        return {
            "type": "ir.actions.act_window",
            "res_model": "project.mcp.apikey.description",
            "name": _("New Project MCP API Key"),
            "target": "new",
            "views": [(False, "form")],
        }


class ProjectMCPAPIKeyDescription(models.TransientModel):
    _name = "project.mcp.apikey.description"
    _description = "Project MCP API Key Description"

    name = fields.Char(string="Description", required=True)

    @check_identity
    def make_key(self):
        self.ensure_one()
        if not self.env.user.has_group("project_mcp.group_project_mcp_user"):
            raise AccessError(_("This user is not enabled for Project MCP API access."))
        key = self.env["res.users.apikeys"]._generate("project_mcp", self.sudo().name)
        self.unlink()
        return {
            "type": "ir.actions.act_window",
            "res_model": "project.mcp.apikey.show",
            "name": _("Project MCP API Key Ready"),
            "target": "new",
            "views": [(False, "form")],
            "context": {"default_key": key},
        }


class ProjectMCPAPIKeyShow(models.AbstractModel):
    _name = "project.mcp.apikey.show"
    _description = "Show Project MCP API Key"

    id = fields.Id()
    key = fields.Char(readonly=True)
