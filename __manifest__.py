{
    "name": "Project MCP",
    "summary": "Restricted REST API for MCP agents working with Project tasks",
    "version": "17.0.2.0.0",
    "category": "Services/Project",
    "author": "Community",
    "license": "LGPL-3",
    "depends": ["project", "mail"],
    "data": [
        "security/project_mcp_security.xml",
        "security/ir.model.access.csv",
        "views/api_key_views.xml",
        "views/audit_log_views.xml",
        "views/project_task_views.xml",
    ],
    "installable": True,
    "application": False,
}
