import functools
import hmac
import logging
import re
import uuid

from datetime import datetime
from urllib.parse import unquote, urlparse

from odoo import Command, fields, http
from odoo.exceptions import AccessDenied, AccessError, MissingError, UserError, ValidationError
from odoo.http import request
from odoo.tools import html2plaintext, plaintext2html
from werkzeug.exceptions import RequestEntityTooLarge

_logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_PAGE_SIZE = 100
MAX_TEXT_LENGTH = 30000
MAX_IDS = 50
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
DATETIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")

# Body fields that map to task values, and the extra keys each endpoint accepts.
TASK_VALUE_FIELDS = {
    "name",
    "description",
    "description_html",
    "priority",
    "deadline",
    "allocated_hours",
    "tags",
    "project_id",
    "parent_id",
    "acceptance_criteria",
    "test_results",
    "git_repository",
    "pull_request_url",
    "deployment_environment",
    "verification_evidence",
    "ai_blockers",
}
TASK_UPDATE_FIELDS = (TASK_VALUE_FIELDS - {"project_id", "parent_id"}) | {
    "note",
    "expected_write_date",
}
TASK_CREATE_FIELDS = TASK_VALUE_FIELDS | {
    "note",
    "stage_id",
    "stage_name",
    "assignee_ids",
    "assignee_logins",
    "agent",
}
ASSIGNEE_FIELDS = {
    "mode",
    "assignee_ids",
    "assignee_logins",
    "note",
    "expected_write_date",
}
DEPENDENCY_FIELDS = {"mode", "dependency_ids", "note", "expected_write_date"}


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
            actor_identifier = request.httprequest.headers.get("X-MCP-Actor-ID", "").strip()
            actor_name = unquote(
                request.httprequest.headers.get("X-MCP-Actor-Name", "").strip()
            )
            if not re.fullmatch(r"[A-Za-z0-9_.@+-]{1,128}", actor_identifier):
                actor_identifier = False
            if not actor_name or len(actor_name) > 128:
                actor_name = False
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
                        "actor_identifier": actor_identifier,
                        "actor_name": actor_name,
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

    def _check_fields(self, body, allowed_fields):
        unknown = sorted(set(body) - set(allowed_fields))
        if unknown:
            raise MCPAPIError(
                400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}."
            )

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

    def _integer(self, body, name, *, required=False, minimum=1, maximum=2**31 - 1):
        value = body.get(name)
        if value is None:
            if required:
                raise MCPAPIError(400, "missing_field", f"Field '{name}' is required.")
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be an integer.")
        if value < minimum or value > maximum:
            raise MCPAPIError(
                400, "invalid_field", f"Field '{name}' must be between {minimum} and {maximum}."
            )
        return value

    def _number(self, body, name, *, minimum=0.0, maximum=100000.0):
        value = body.get(name)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be a number.")
        if value < minimum or value > maximum:
            raise MCPAPIError(
                400, "invalid_field", f"Field '{name}' must be between {minimum} and {maximum}."
            )
        return float(value)

    def _id_list(self, body, name):
        value = body.get(name)
        if value is None:
            return None
        if not isinstance(value, list):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be a list of record ids.")
        if len(value) > MAX_IDS:
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' accepts at most {MAX_IDS} ids.")
        for item in value:
            if isinstance(item, bool) or not isinstance(item, int) or item < 1:
                raise MCPAPIError(
                    400, "invalid_field", f"Field '{name}' must only contain positive integers."
                )
        return list(dict.fromkeys(value))

    def _name_list(self, body, name, *, maximum_items=20, maximum=128):
        value = body.get(name)
        if value is None:
            return None
        if not isinstance(value, list):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be a list of strings.")
        if len(value) > maximum_items:
            raise MCPAPIError(
                400, "invalid_field", f"Field '{name}' accepts at most {maximum_items} values."
            )
        names = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise MCPAPIError(
                    400, "invalid_field", f"Field '{name}' must only contain non-empty strings."
                )
            item = item.strip()
            if len(item) > maximum:
                raise MCPAPIError(
                    400, "invalid_field", f"Values of '{name}' exceed {maximum} characters."
                )
            if item not in names:
                names.append(item)
        return names

    def _datetime(self, body, name):
        """Return a datetime for the given field, or False when the value must be cleared."""
        value = body.get(name)
        if value is None:
            return False
        if not isinstance(value, str):
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be a string or null.")
        value = value.strip()
        if not value:
            return False
        for date_format in DATETIME_FORMATS:
            try:
                return datetime.strptime(value, date_format)
            except ValueError:
                continue
        raise MCPAPIError(
            400,
            "invalid_field",
            f"Field '{name}' must be 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS' (UTC).",
        )

    def _expected_write_date(self, body):
        if "expected_write_date" not in body:
            return None
        value = self._string(body, "expected_write_date", required=True, maximum=32)
        normalized = value.replace("T", " ").removesuffix("Z")
        try:
            parsed = fields.Datetime.to_datetime(normalized)
        except (TypeError, ValueError):
            parsed = None
        if not parsed:
            raise MCPAPIError(
                400,
                "invalid_field",
                "Field 'expected_write_date' must use the write_date returned by get_task.",
            )
        return fields.Datetime.to_string(parsed)

    def _lock_and_check_version(self, task, expected_write_date):
        """Lock the row and reject a stale update instead of overwriting newer work."""
        if expected_write_date is None:
            return
        request.env.cr.execute(
            "SELECT write_date FROM project_task WHERE id = %s FOR UPDATE", [task.id]
        )
        row = request.env.cr.fetchone()
        current = fields.Datetime.to_string(row[0]) if row and row[0] else None
        if current != expected_write_date:
            raise MCPAPIError(
                409,
                "stale_task",
                "The task changed after it was read. Read it again before updating.",
            )

    def _url(self, body, name):
        value = self._string(body, name, maximum=1024)
        if not value:
            return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise MCPAPIError(400, "invalid_field", f"Field '{name}' must be an HTTP(S) URL.")
        return value

    def _selection(self, body, name, field_name):
        value = self._string(body, name, required=True, maximum=64)
        allowed = request.env["project.task"]._fields[field_name].get_values(request.env)
        if value not in allowed:
            raise MCPAPIError(
                400, "invalid_field", f"Field '{name}' must be one of: {', '.join(allowed)}."
            )
        return value

    def _append_active_filter(self, domain):
        active = request.httprequest.args.get("active", "true").lower()
        if active not in {"true", "false", "all"}:
            raise MCPAPIError(400, "invalid_filter", "active must be true, false, or all.")
        if active != "all":
            domain.append(("active", "=", active == "true"))
        return active

    def _task_filter_domain(self):
        args = request.httprequest.args
        domain = []
        name = args.get("name", "").strip()
        if name:
            if len(name) > 100:
                raise MCPAPIError(400, "invalid_filter", "Task name filter is too long.")
            domain.append(("name", "ilike", name))
        ai_status = args.get("ai_status", "").strip()
        if ai_status:
            allowed = {
                item[0] for item in request.env["project.task"]._fields["ai_status"].selection
            }
            if ai_status not in allowed:
                raise MCPAPIError(400, "invalid_filter", "Unknown ai_status value.")
            domain.append(("ai_status", "=", ai_status))
        task_state = args.get("task_state", "").strip()
        if task_state:
            allowed = set(request.env["project.task"]._fields["state"].get_values(request.env))
            if task_state not in allowed:
                raise MCPAPIError(400, "invalid_filter", "Unknown task_state value.")
            domain.append(("state", "=", task_state))
        for argument, field_name in (
            ("project_id", "project_id"),
            ("stage_id", "stage_id"),
            ("assignee_id", "user_ids"),
            ("parent_id", "parent_id"),
        ):
            raw = args.get(argument, "").strip()
            if not raw:
                continue
            try:
                value = int(raw)
            except ValueError:
                raise MCPAPIError(
                    400, "invalid_filter", f"{argument} must be an integer."
                ) from None
            if value < 1:
                raise MCPAPIError(400, "invalid_filter", f"{argument} must be a positive integer.")
            domain.append((field_name, "=", value))
        return domain

    def _users(self, body):
        """Resolve assignees from ``assignee_ids`` and/or ``assignee_logins``."""
        user_ids = self._id_list(body, "assignee_ids")
        logins = self._name_list(body, "assignee_logins")
        user_model = request.env["res.users"]
        users = user_model.browse()
        if user_ids:
            users = user_model.search([("id", "in", user_ids)])
            missing = sorted(set(user_ids) - set(users.ids))
            if missing:
                raise MCPAPIError(
                    400,
                    "invalid_field",
                    f"Unknown or not visible user id(s): {', '.join(str(i) for i in missing)}.",
                )
        for login in logins or []:
            user = user_model.search([("login", "=", login)], limit=1)
            if not user:
                raise MCPAPIError(400, "invalid_field", f"Unknown user login '{login}'.")
            users |= user
        shared = users.filtered("share")
        if shared:
            raise MCPAPIError(
                400,
                "invalid_field",
                f"Portal users cannot be assignees: {', '.join(shared.mapped('login'))}.",
            )
        return users

    def _tasks_from_ids(self, task_ids):
        task_model = request.env["project.task"]
        tasks = task_model.search([("id", "in", task_ids or [])])
        missing = sorted(set(task_ids or []) - set(tasks.ids))
        if missing:
            raise MCPAPIError(
                400,
                "invalid_field",
                f"Unknown or not visible task id(s): {', '.join(str(i) for i in missing)}.",
            )
        return tasks

    def _tags(self, names):
        tag_model = request.env["project.tags"]
        tags = tag_model.browse()
        for name in names:
            tag = tag_model.search([("name", "=ilike", name)], limit=1)
            if not tag:
                tag = tag_model.create({"name": name})
            tags |= tag
        return tags

    def _task_values(self, body, allowed_fields):
        """Validate a task payload and return the values to write."""
        unknown = sorted(set(body) - allowed_fields)
        if unknown:
            raise MCPAPIError(
                400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}."
            )
        if "description" in body and "description_html" in body:
            raise MCPAPIError(
                400,
                "invalid_field",
                "Provide either 'description' or 'description_html', not both.",
            )
        values = {}
        if "name" in body:
            values["name"] = self._string(body, "name", required=True, maximum=255)
        if "description" in body:
            text = self._string(body, "description", maximum=MAX_TEXT_LENGTH)
            values["description"] = plaintext2html(text) if text else False
        if "description_html" in body:
            html = self._string(body, "description_html", maximum=MAX_TEXT_LENGTH)
            values["description"] = html or False
        if "priority" in body:
            values["priority"] = self._selection(body, "priority", "priority")
        if "deadline" in body:
            values["date_deadline"] = self._datetime(body, "deadline")
        if "allocated_hours" in body:
            values["allocated_hours"] = self._number(body, "allocated_hours") or 0.0
        if "tags" in body:
            values["tag_ids"] = [Command.set(self._tags(self._name_list(body, "tags") or []).ids)]
        if "project_id" in body:
            values["project_id"] = self._project(
                self._integer(body, "project_id", required=True)
            ).id
        if "parent_id" in body:
            parent_id = self._integer(body, "parent_id")
            values["parent_id"] = self._task(parent_id).id if parent_id else False
        for api_name, field_name in (
            ("acceptance_criteria", "acceptance_criteria"),
            ("test_results", "test_results"),
            ("deployment_environment", "deployment_environment"),
            ("verification_evidence", "verification_evidence"),
            ("ai_blockers", "ai_blockers"),
        ):
            if api_name in body:
                maximum = 128 if api_name == "deployment_environment" else MAX_TEXT_LENGTH
                values[field_name] = self._string(body, api_name, maximum=maximum) or False
        if "git_repository" in body:
            values["git_repository"] = self._string(
                body, "git_repository", maximum=1024
            ) or False
        if "pull_request_url" in body:
            values["pull_request_url"] = self._url(body, "pull_request_url") or False
        return values

    def _serialize_stage(self, stage):
        return {
            "id": stage.id,
            "name": stage.name,
            "sequence": stage.sequence,
            "folded": stage.fold,
        }

    def _serialize_message(self, message):
        return {
            "id": message.id,
            "date": fields.Datetime.to_string(message.date) if message.date else None,
            "author": message.author_id.name or message.email_from or None,
            "message_type": message.message_type,
            "subtype": message.subtype_id.name or None,
            "internal_note": bool(message.subtype_id.internal),
            "body_text": html2plaintext(message.body or ""),
        }

    def _visible_task_links(self, tasks):
        visible = request.env["project.task"].search([("id", "in", tasks.ids)], order="id")
        return [
            {"id": task.id, "name": task.name, "state": task.state} for task in visible
        ]

    def _task(self, task_id, operation="read", *, include_archived=False):
        task_model = request.env["project.task"]
        if include_archived:
            task_model = task_model.with_context(active_test=False)
        task_model.check_access_rights(operation)
        task = task_model.search([("id", "=", task_id)], limit=1)
        if not task:
            raise MCPAPIError(404, "not_found", "Task not found or not visible to this user.")
        task.check_access_rule(operation)
        return task

    def _project(self, project_id):
        project = request.env["project.project"].search([("id", "=", project_id)], limit=1)
        if not project:
            raise MCPAPIError(404, "not_found", "Project not found or not visible to this user.")
        return project

    def _serialize_project(self, project):
        task_count = request.env["project.task"].search_count([("project_id", "=", project.id)])
        result = {
            "id": project.id,
            "name": project.name,
            "active": project.active,
            "company_id": project.company_id.id or None,
            "company_name": project.company_id.name or None,
            "task_count_visible": task_count,
            "task_dependencies_enabled": project.allow_task_dependencies,
        }
        if "allow_timesheets" in project._fields:
            result["timesheets_enabled"] = project.allow_timesheets
        return result

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
            "dependencies": self._visible_task_links(task.depend_on_ids),
            "blocks": self._visible_task_links(task.dependent_ids),
            "tags": [tag.name for tag in task.tag_ids],
            "allocated_hours": task.allocated_hours,
            "deadline": fields.Date.to_string(task.date_deadline) if task.date_deadline else None,
            "deadline_datetime": fields.Datetime.to_string(task.date_deadline)
            if task.date_deadline
            else None,
            "ai_status": task.ai_status,
            "ai_agent": task.ai_agent or None,
            "git_branch": task.git_branch or None,
            "git_commit": task.git_commit or None,
            "ai_summary": task.ai_summary or None,
            "verification_status": task.verification_status,
            "verification_notes": task.verification_notes or None,
            "acceptance_criteria": task.acceptance_criteria or None,
            "test_results": task.test_results or None,
            "git_repository": task.git_repository or None,
            "pull_request_url": task.pull_request_url or None,
            "deployment_environment": task.deployment_environment or None,
            "verification_evidence": task.verification_evidence or None,
            "ai_blockers": task.ai_blockers or None,
            "ai_started_at": fields.Datetime.to_string(task.ai_started_at)
            if task.ai_started_at
            else None,
            "ai_completed_at": fields.Datetime.to_string(task.ai_completed_at)
            if task.ai_completed_at
            else None,
            "ai_verified_at": fields.Datetime.to_string(task.ai_verified_at)
            if task.ai_verified_at
            else None,
            "create_date": fields.Datetime.to_string(task.create_date)
            if task.create_date
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
        active = self._append_active_filter(domain)

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
        project = self._project(project_id)
        domain = [("project_id", "=", project.id)] + self._task_filter_domain()
        active = self._append_active_filter(domain)
        task_model = request.env["project.task"]
        if active != "true":
            task_model = task_model.with_context(active_test=False)
        tasks = task_model.search(
            domain, limit=limit, offset=offset, order="priority desc, sequence, id"
        )
        total = task_model.search_count(domain)
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
        include_archived = request.httprequest.args.get("include_archived", "false").lower()
        if include_archived not in {"true", "false"}:
            raise MCPAPIError(400, "invalid_filter", "include_archived must be true or false.")
        return self._serialize_task(
            self._task(task_id, include_archived=include_archived == "true")
        )

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
        self._check_fields(
            body, {"agent", "git_branch", "git_repository", "expected_write_date"}
        )
        agent = self._string(body, "agent", required=True, maximum=128)
        branch = self._string(body, "git_branch", maximum=255)
        repository = self._string(body, "git_repository", maximum=1024)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_start(agent=agent, branch=branch, repository=repository)
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
        self._check_fields(body, {"comment", "expected_write_date"})
        comment = self._string(body, "comment", required=True, maximum=12000)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
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
        self._check_fields(
            body,
            {
                "summary",
                "agent",
                "git_branch",
                "git_commit",
                "test_results",
                "pull_request_url",
                "deployment_environment",
                "mark_done",
                "expected_write_date",
            },
        )
        summary = self._string(body, "summary", required=True, maximum=12000)
        agent = self._string(body, "agent", maximum=128)
        branch = self._string(body, "git_branch", maximum=255)
        commit = self._string(body, "git_commit", maximum=64)
        test_results = self._string(body, "test_results", maximum=MAX_TEXT_LENGTH)
        pull_request_url = self._url(body, "pull_request_url")
        deployment_environment = self._string(
            body, "deployment_environment", maximum=128
        )
        if commit and not COMMIT_RE.fullmatch(commit):
            raise MCPAPIError(
                400, "invalid_field", "git_commit must be a 7-64 character hexadecimal hash."
            )
        mark_done = self._boolean(body, "mark_done", True)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_complete(
            summary=summary,
            agent=agent,
            branch=branch,
            commit=commit,
            test_results=test_results,
            pull_request_url=pull_request_url,
            deployment_environment=deployment_environment,
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
        self._check_fields(
            body,
            {
                "result",
                "notes",
                "evidence",
                "agent",
                "update_task_state",
                "expected_write_date",
            },
        )
        result = self._string(body, "result", required=True, maximum=16)
        if result not in {"passed", "failed"}:
            raise MCPAPIError(400, "invalid_field", "result must be 'passed' or 'failed'.")
        notes = self._string(body, "notes", required=True, maximum=12000)
        evidence = self._string(body, "evidence", maximum=MAX_TEXT_LENGTH)
        agent = self._string(body, "agent", maximum=128)
        update_task_state = self._boolean(body, "update_task_state", True)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_verify(
            result=result,
            notes=notes,
            agent=agent,
            evidence=evidence,
            update_task_state=update_task_state,
        )
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/projects/<int:project_id>/stages",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("list_stages")
    def list_stages(self, project_id, **_params):
        project = self._project(project_id)
        stages = request.env["project.task.type"].search(
            [("project_ids", "=", project.id)], order="sequence, id"
        )
        return {
            "project": {"id": project.id, "name": project.name},
            "items": [self._serialize_stage(stage) for stage in stages],
            "total": len(stages),
        }

    @http.route(
        "/mcp/v1/tasks",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("search_tasks")
    def search_tasks(self, **_params):
        limit, offset = self._pagination()
        domain = self._task_filter_domain()
        active = self._append_active_filter(domain)
        task_model = request.env["project.task"]
        if active != "true":
            task_model = task_model.with_context(active_test=False)
        tasks = task_model.search(domain, limit=limit, offset=offset, order="write_date desc, id")
        return {
            "items": [self._serialize_task(task, include_description=False) for task in tasks],
            "total": task_model.search_count(domain),
            "limit": limit,
            "offset": offset,
        }

    @http.route(
        "/mcp/v1/tasks",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("create_task")
    def create_task(self, **_params):
        body = self._json_body()
        values = self._task_values(body, TASK_CREATE_FIELDS)
        if not values.get("name"):
            raise MCPAPIError(400, "missing_field", "Field 'name' is required.")
        if not values.get("project_id"):
            raise MCPAPIError(400, "missing_field", "Field 'project_id' is required.")
        if values.get("parent_id"):
            parent = self._task(values["parent_id"])
            if parent.project_id.id != values["project_id"]:
                raise MCPAPIError(
                    400,
                    "invalid_field",
                    "The parent task must belong to the selected project.",
                )
        agent = self._string(body, "agent", maximum=128)
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        stage_id = self._integer(body, "stage_id")
        stage_name = self._string(body, "stage_name", maximum=128)
        users = self._users(body)
        if users:
            values["user_ids"] = [Command.set(users.ids)]
        task = request.env["project.task"]._mcp_create_task(values, agent=agent)
        if note:
            task._mcp_post_note("MCP: task creation note", note)
        if stage_id or stage_name:
            task._mcp_move_stage(stage_id=stage_id, stage_name=stage_name)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/update",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("update_task")
    def update_task(self, task_id, **_params):
        body = self._json_body()
        values = self._task_values(body, TASK_UPDATE_FIELDS)
        if not values:
            raise MCPAPIError(400, "missing_field", "At least one field to update is required.")
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_update(values, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/stage",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("move_task_stage")
    def move_task_stage(self, task_id, **_params):
        body = self._json_body()
        unknown = sorted(
            set(body) - {"stage_id", "stage_name", "note", "expected_write_date"}
        )
        if unknown:
            raise MCPAPIError(400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}.")
        stage_id = self._integer(body, "stage_id")
        stage_name = self._string(body, "stage_name", maximum=128)
        if not stage_id and not stage_name:
            raise MCPAPIError(400, "missing_field", "Field 'stage_id' or 'stage_name' is required.")
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_move_stage(stage_id=stage_id, stage_name=stage_name, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/state",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("set_task_state")
    def set_task_state(self, task_id, **_params):
        body = self._json_body()
        unknown = sorted(set(body) - {"state", "note", "expected_write_date"})
        if unknown:
            raise MCPAPIError(400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}.")
        state = self._selection(body, "state", "state")
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_set_state(state, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/assignees",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("set_task_assignees")
    def set_task_assignees(self, task_id, **_params):
        body = self._json_body()
        unknown = sorted(set(body) - ASSIGNEE_FIELDS)
        if unknown:
            raise MCPAPIError(400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}.")
        mode = self._string(body, "mode", maximum=16) or "set"
        if mode not in {"set", "add", "remove"}:
            raise MCPAPIError(400, "invalid_field", "mode must be 'set', 'add' or 'remove'.")
        users = self._users(body)
        if mode != "set" and not users:
            raise MCPAPIError(
                400,
                "missing_field",
                "Field 'assignee_ids' or 'assignee_logins' is required for this mode.",
            )
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_set_assignees(users, mode=mode, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/dependencies",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("set_task_dependencies")
    def set_task_dependencies(self, task_id, **_params):
        body = self._json_body()
        self._check_fields(body, DEPENDENCY_FIELDS)
        mode = self._string(body, "mode", maximum=16) or "set"
        if mode not in {"set", "add", "remove"}:
            raise MCPAPIError(400, "invalid_field", "mode must be 'set', 'add' or 'remove'.")
        dependency_ids = self._id_list(body, "dependency_ids")
        if dependency_ids is None:
            raise MCPAPIError(400, "missing_field", "Field 'dependency_ids' is required.")
        if mode != "set" and not dependency_ids:
            raise MCPAPIError(
                400, "invalid_field", "dependency_ids cannot be empty for add or remove."
            )
        dependencies = self._tasks_from_ids(dependency_ids)
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_set_dependencies(dependencies, mode=mode, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/worklogs",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("log_work")
    def log_work(self, task_id, **_params):
        body = self._json_body()
        self._check_fields(
            body, {"description", "hours", "date", "expected_write_date"}
        )
        if "account.analytic.line" not in request.env.registry.models:
            raise MCPAPIError(
                409,
                "feature_unavailable",
                "Timesheets is not installed in this Odoo database.",
            )
        description = self._string(body, "description", required=True, maximum=2000)
        hours = self._number(body, "hours", minimum=0.01, maximum=24.0)
        if hours is None:
            raise MCPAPIError(400, "missing_field", "Field 'hours' is required.")
        work_date = fields.Date.context_today(request.env.user)
        if "date" in body:
            parsed_date = self._datetime(body, "date")
            if not parsed_date:
                raise MCPAPIError(400, "invalid_field", "Field 'date' cannot be empty.")
            work_date = parsed_date.date()
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        if not task.project_id or not task.project_id.allow_timesheets:
            raise MCPAPIError(
                409,
                "feature_unavailable",
                "Timesheets are not enabled for this task's project.",
            )
        line_model = request.env["account.analytic.line"]
        line_model.check_access_rights("create")
        line = line_model.create(
            {
                "name": description,
                "unit_amount": hours,
                "date": work_date,
                "task_id": task.id,
                "project_id": task.project_id.id,
                "user_id": request.env.user.id,
            }
        )
        task._mcp_post_note("MCP: work logged", f"{hours:g} hour(s): {description}")
        return {
            "id": line.id,
            "task_id": task.id,
            "hours": line.unit_amount,
            "date": fields.Date.to_string(line.date),
            "description": line.name,
        }

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/archive",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("archive_task")
    def archive_task(self, task_id, **_params):
        body = self._json_body()
        unknown = sorted(set(body) - {"note", "expected_write_date"})
        if unknown:
            raise MCPAPIError(400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}.")
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write")
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_set_active(False, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/unarchive",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
        max_content_length=MAX_BODY_BYTES,
    )
    @api_endpoint("unarchive_task")
    def unarchive_task(self, task_id, **_params):
        body = self._json_body()
        unknown = sorted(set(body) - {"note", "expected_write_date"})
        if unknown:
            raise MCPAPIError(400, "invalid_field", f"Unsupported field(s): {', '.join(unknown)}.")
        note = self._string(body, "note", maximum=MAX_TEXT_LENGTH)
        task = self._task(task_id, "write", include_archived=True)
        self._lock_and_check_version(task, self._expected_write_date(body))
        task._mcp_set_active(True, note=note)
        return self._serialize_task(task)

    @http.route(
        "/mcp/v1/tasks/<int:task_id>/comments",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("list_comments")
    def list_comments(self, task_id, **_params):
        limit, offset = self._pagination()
        task = self._task(task_id, include_archived=True)
        domain = [
            ("model", "=", "project.task"),
            ("res_id", "=", task.id),
            ("message_type", "in", ["comment", "notification"]),
        ]
        message_model = request.env["mail.message"]
        messages = message_model.search(domain, limit=limit, offset=offset, order="date desc, id desc")
        return {
            "task_id": task.id,
            "items": [self._serialize_message(message) for message in messages],
            "total": message_model.search_count(domain),
            "limit": limit,
            "offset": offset,
        }

    @http.route(
        "/mcp/v1/projects/<int:project_id>/members",
        type="http",
        auth="public",
        methods=["GET"],
        csrf=False,
        save_session=False,
    )
    @api_endpoint("list_project_members")
    def list_project_members(self, project_id, **_params):
        project = self._project(project_id)
        member_ids = set(project.favorite_user_ids.ids)
        if project.user_id:
            member_ids.add(project.user_id.id)
        member_ids.update(
            request.env["project.task"]
            .search([("project_id", "=", project.id)])
            .mapped("user_ids")
            .ids
        )
        users = request.env["res.users"].search(
            [("id", "in", list(member_ids)), ("share", "=", False), ("active", "=", True)],
            order="name, id",
        )
        return {
            "project": {"id": project.id, "name": project.name},
            "items": [
                {"id": user.id, "name": user.name, "login": user.login, "email": user.email or None}
                for user in users
            ],
            "total": len(users),
        }
