import functools
import hmac
import logging
import re
import uuid

from odoo import fields, http
from odoo.exceptions import AccessDenied, AccessError, MissingError, UserError, ValidationError
from odoo.http import request
from odoo.tools import html2plaintext
from werkzeug.exceptions import RequestEntityTooLarge

_logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_PAGE_SIZE = 100
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


class MCPAPIError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def api_endpoint(action):
    def decorate(method):
        @functools.wraps(method)
        def wrapped(self, *args, **kwargs):
            request_id = self._request_id()
            try:
                self._authenticate()
                data = method(self, *args, **kwargs)
                self._audit(action, "success", 200, request_id, kwargs)
                return self._response(data=data, status=200, request_id=request_id)
            except MCPAPIError as exc:
                request.env.cr.rollback()
                self._audit(action, "error", exc.status, request_id, kwargs, exc.code)
                return self._response(
                    error={"code": exc.code, "message": exc.message},
                    status=exc.status,
                    request_id=request_id,
                )
            except AccessDenied:
                request.env.cr.rollback()
                self._audit(action, "error", 401, request_id, kwargs, "unauthorized")
                return self._response(
                    error={"code": "unauthorized", "message": "Invalid API credentials."},
                    status=401,
                    request_id=request_id,
                )
            except AccessError:
                request.env.cr.rollback()
                self._audit(action, "error", 403, request_id, kwargs, "forbidden")
                return self._response(
                    error={
                        "code": "forbidden",
                        "message": "Access denied for this record or operation.",
                    },
                    status=403,
                    request_id=request_id,
                )
            except MissingError:
                request.env.cr.rollback()
                self._audit(action, "error", 404, request_id, kwargs, "not_found")
                return self._response(
                    error={"code": "not_found", "message": "The requested record does not exist."},
                    status=404,
                    request_id=request_id,
                )
            except (ValidationError, UserError) as exc:
                request.env.cr.rollback()
                self._audit(action, "error", 400, request_id, kwargs, "validation_error")
                return self._response(
                    error={"code": "validation_error", "message": str(exc)},
                    status=400,
                    request_id=request_id,
                )
            except RequestEntityTooLarge:
                request.env.cr.rollback()
                self._audit(action, "error", 413, request_id, kwargs, "payload_too_large")
                return self._response(
                    error={"code": "payload_too_large", "message": "Request body exceeds 64 KiB."},
                    status=413,
                    request_id=request_id,
                )
            except Exception:
                request.env.cr.rollback()
                _logger.exception(
                    "Unexpected Project MCP API error request_id=%s action=%s", request_id, action
                )
                self._audit(action, "error", 500, request_id, kwargs, "internal_error")
                return self._response(
                    error={"code": "internal_error", "message": "Unexpected server error."},
                    status=500,
                    request_id=request_id,
                )

        return wrapped

    return decorate


class ProjectMCPController(http.Controller):
    def _request_id(self):
        supplied = request.httprequest.headers.get("X-Request-ID", "")
        return supplied if REQUEST_ID_RE.fullmatch(supplied) else str(uuid.uuid4())

    def _response(self, *, data=None, error=None, status, request_id):
        payload = {"ok": error is None, "request_id": request_id}
        if error is None:
            payload["data"] = data
        else:
            payload["error"] = error
        return request.make_json_response(
            payload,
            status=status,
            headers=[
                ("X-Request-ID", request_id),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )

    def _authenticate(self):
        authorization = request.httprequest.headers.get("Authorization", "")
        scheme, separator, api_key = authorization.partition(" ")
        api_key = api_key.strip()
        if separator != " " or scheme.lower() != "bearer" or not api_key:
            raise AccessDenied()
        if len(api_key) > 256:
            raise AccessDenied()

        uid = (
            request.env["res.users.apikeys"]
            .sudo()
            ._check_credentials(scope="project_mcp", key=api_key)
        )
        if not uid:
            raise AccessDenied()

        user = request.env["res.users"].sudo().browse(uid).exists()
        if not user or not user.active:
            raise AccessDenied()

        expected_login = request.httprequest.headers.get("X-Odoo-Login", "").strip()
        if expected_login and not hmac.compare_digest(user.login or "", expected_login):
            raise AccessDenied()

        request.update_env(user=user.id)
        if not request.env.user.has_group("project_mcp.group_project_mcp_user"):
            raise AccessError("The user is not enabled for Project MCP API access.")

    def _audit(self, action, outcome, http_status, request_id, route_values, error_code=None):
        try:
            task_id = route_values.get("task_id")
            project_id = route_values.get("project_id")
            if task_id and not request.env["project.task"].sudo().browse(task_id).exists():
                task_id = False
            if project_id and not request.env["project.project"].sudo().browse(project_id).exists():
                project_id = False
            public_user = request.env.ref("base.public_user", raise_if_not_found=False)
            user_id = (
                request.env.uid if request.env.uid and request.env.user != public_user else False
            )
            details = {
                "method": request.httprequest.method,
                "path": request.httprequest.path,
            }
            if route_values.get("task_id"):
                details["requested_task_id"] = route_values["task_id"]
            if route_values.get("project_id"):
                details["requested_project_id"] = route_values["project_id"]
            if error_code:
                details["error_code"] = error_code
            with request.env.cr.savepoint():
                request.env["project.mcp.audit.log"].sudo().create(
                    {
                        "request_id": request_id,
                        "action": action,
                        "outcome": outcome,
                        "http_status": http_status,
                        "user_id": user_id,
                        "project_id": project_id,
                        "task_id": task_id,
                        "source_ip": (request.httprequest.remote_addr or "")[:64],
                        "user_agent": (request.httprequest.user_agent.string or "")[:255],
                        "details": details,
                    }
                )
            _logger.info(
                "Project MCP API request_id=%s action=%s outcome=%s status=%s uid=%s task_id=%s project_id=%s",
                request_id,
                action,
                outcome,
                http_status,
                user_id,
                task_id,
                project_id,
            )
        except Exception:
            _logger.exception("Could not write Project MCP audit record request_id=%s", request_id)

    def _json_body(self):
        if (
            request.httprequest.content_length
            and request.httprequest.content_length > MAX_BODY_BYTES
        ):
            raise MCPAPIError(413, "payload_too_large", "Request body exceeds 64 KiB.")
        if request.httprequest.mimetype != "application/json":
            raise MCPAPIError(
                415, "unsupported_media_type", "Content-Type must be application/json."
            )
        try:
            body = request.get_json_data()
        except (TypeError, ValueError):
            raise MCPAPIError(400, "invalid_json", "Request body is not valid JSON.") from None
        if not isinstance(body, dict):
            raise MCPAPIError(400, "invalid_body", "Request body must be a JSON object.")
        return body

    def _string(self, body, name, *, required=False, maximum=255):
        value = body.get(name)
        if value is None:
            if required:
                raise MCPAPIError(400, "missing_field", f"Field '{name}' is required.")
            return None
        if not isinstance(value, str):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be a string.")
        value = value.strip()
        if required and not value:
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' cannot be empty.")
        if len(value) > maximum:
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' exceeds {maximum} characters.")
        if any(ord(character) < 32 and character not in "\n\r\t" for character in value):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' contains control characters.")
        return value or None

    def _boolean(self, body, name, default):
        value = body.get(name, default)
        if not isinstance(value, bool):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be a boolean.")
        return value

    def _pagination(self):
        try:
            limit = int(request.httprequest.args.get("limit", 50))
            offset = int(request.httprequest.args.get("offset", 0))
        except (TypeError, ValueError):
            raise MCPAPIError(
                400, "invalid_pagination", "limit and offset must be integers."
            ) from None
        if limit < 1 or limit > MAX_PAGE_SIZE or offset < 0:
            raise MCPAPIError(
                400, "invalid_pagination", "limit must be 1-100 and offset must be non-negative."
            )
        return limit, offset

    def _task(self, task_id, operation="read"):
        task_model = request.env["project.task"]
        task_model.check_access_rights(operation)
        task = task_model.search([("id", "=", task_id)], limit=1)
        if not task:
            raise MCPAPIError(404, "not_found", "Task not found or not visible to this user.")
        task.check_access_rule(operation)
        return task

    def _serialize_project(self, project):
        task_count = request.env["project.task"].search_count([("project_id", "=", project.id)])
        return {
            "id": project.id,
            "name": project.name,
            "active": project.active,
            "company_id": project.company_id.id or None,
            "company_name": project.company_id.name or None,
            "task_count_visible": task_count,
        }

    def _serialize_task(self, task, *, include_description=True):
        result = {
            "id": task.id,
            "name": task.name,
            "project_id": task.project_id.id or None,
            "project_name": task.project_id.name or None,
            "parent_id": task.parent_id.id or None,
            "stage_id": task.stage_id.id or None,
            "stage_name": task.stage_id.name or None,
            "state": task.state,
            "priority": task.priority,
            "active": task.active,
            "assignees": [{"id": user.id, "name": user.name} for user in task.user_ids],
            "deadline": fields.Date.to_string(task.date_deadline) if task.date_deadline else None,
            "ai_status": task.ai_status,
            "ai_agent": task.ai_agent or None,
            "git_branch": task.git_branch or None,
            "git_commit": task.git_commit or None,
            "ai_summary": task.ai_summary or None,
            "verification_status": task.verification_status,
            "verification_notes": task.verification_notes or None,
            "ai_started_at": fields.Datetime.to_string(task.ai_started_at)
            if task.ai_started_at
            else None,
            "ai_completed_at": fields.Datetime.to_string(task.ai_completed_at)
            if task.ai_completed_at
            else None,
            "ai_verified_at": fields.Datetime.to_string(task.ai_verified_at)
            if task.ai_verified_at
            else None,
            "write_date": fields.Datetime.to_string(task.write_date) if task.write_date else None,
        }
        if include_description:
            result["description_html"] = task.description or ""
            result["description_text"] = html2plaintext(task.description or "")
        return result

    @http.route(
        "/mcp/v1/projects",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("list_projects")
    def list_projects(self, **_params):
        limit, offset = self._pagination()
        domain = []
        name = request.httprequest.args.get("name", "").strip()
        if name:
            if len(name) > 100:
                raise MCPAPIError(400, "invalid_filter", "Project name filter is too long.")
            domain.append(("name", "ilike", name))
        active = request.httprequest.args.get("active", "true").lower()
        if active not in {"true", "false", "all"}:
            raise MCPAPIError(400, "invalid_filter", "active must be true, false, or all.")
        if active != "all":
            domain.append(("active", "=", active == "true"))

        project_model = request.env["project.project"]
        if active != "true":
            project_model = project_model.with_context(active_test=False)
        projects = project_model.search(domain, limit=limit, offset=offset, order="name, id")
        total = project_model.search_count(domain)
        return {
            "items": [self._serialize_project(project) for project in projects],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @http.route(
        "/mcp/v1/projects/<int:project_id>/tasks",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("list_tasks")
    def list_tasks(self, project_id, **_params):
        limit, offset = self._pagination()
        project = request.env["project.project"].search([("id", "=", project_id)], limit=1)
        if not project:
            raise MCPAPIError(404, "not_found", "Project not found or not visible to this user.")

        domain = [("project_id", "=", project.id)]
        ai_status = request.httprequest.args.get("ai_status", "").strip()
        if ai_status:
            allowed = {
                item[0] for item in request.env["project.task"]._fields["ai_status"].selection
            }
            if ai_status not in allowed:
                raise MCPAPIError(400, "invalid_filter", "Unknown ai_status value.")
            domain.append(("ai_status", "=", ai_status))
        task_state = request.httprequest.args.get("task_state", "").strip()
        if task_state:
            allowed = set(request.env["project.task"]._fields["state"].get_values(request.env))
            if task_state not in allowed:
                raise MCPAPIError(400, "invalid_filter", "Unknown task_state value.")
            domain.append(("state", "=", task_state))

        tasks = request.env["project.task"].search(
            domain, limit=limit, offset=offset, order="priority desc, sequence, id"
        )
        total = request.env["project.task"].search_count(domain)
        return {
            "project": {"id": project.id, "name": project.name},
            "items": [self._serialize_task(task, include_description=False) for task in tasks],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @http.route(
        "/mcp/v1/tasks/<int:task_id>",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("get_task")
    def get_task(self, task_id, **_params):
        return self._serialize_task(self._task(task_id))

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/start",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("start_task")
    def start_task(self, task_id, **_params):
        body = self._json_body()
        agent = self._string(body, "agent", required=True, maximum=128)
        branch = self._string(body, "git_branch", maximum=255)
        task = self._task(task_id, "write")
        task._mcp_start(agent=agent, branch=branch)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/comments",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("add_comment")
    def add_comment(self, task_id, **_params):
        body = self._json_body()
        comment = self._string(body, "comment", required=True, maximum=12000)
        task = self._task(task_id, "write")
        task._mcp_add_comment(comment)
        return {"task_id": task.id, "comment_added": True}

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/complete",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("complete_task")
    def complete_task(self, task_id, **_params):
        body = self._json_body()
        summary = self._string(body, "summary", required=True, maximum=12000)
        agent = self._string(body, "agent", maximum=128)
        branch = self._string(body, "git_branch", maximum=255)
        commit = self._string(body, "git_commit", maximum=64)
        if commit and not COMMIT_RE.fullmatch(commit):
            raise MCPAPIError(
                400, "invalid_field", "git_commit must be a 7-64 character hexadecimal hash."
            )
        mark_done = self._boolean(body, "mark_done", True)
        task = self._task(task_id, "write")
        task._mcp_complete(
            summary=summary,
            agent=agent,
            branch=branch,
            commit=commit,
            mark_done=mark_done,
        )
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/verify",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("verify_task")
    def verify_task(self, task_id, **_params):
        body = self._json_body()
        result = self._string(body, "result", required=True, maximum=16)
        if result not in {"passed", "failed"}:
            raise MCPAPIError(400, "invalid_field", "result must be 'passed' or 'failed'.")
        notes = self._string(body, "notes", required=True, maximum=12000)
        agent = self._string(body, "agent", maximum=128)
        update_task_state = self._boolean(body, "update_task_state", True)
        task = self._task(task_id, "write")
        task._mcp_verify(
            result=result,
            notes=notes,
            agent=agent,
            update_task_state=update_task_state,
        )
        return self._serialize_task(task)
