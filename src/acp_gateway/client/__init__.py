"""Mode B: full ACP v1 client with workspace-scoped fs/*, terminal/*, and permission gates."""

from .fs_handler import WorkspaceFsHandler, is_sensitive_relpath
from .full_client import STOP_REASON_FINISH, FullAcpClient, FullAcpSession, PromptResult
from .permission_policy import (
    VALID_OPTION_KINDS,
    ActionRequest,
    ClientPermissionGate,
    InteractivePermissionGate,
    PolicyPermissionGate,
    sanitize_terminal_text,
    validate_permission_params,
)
from .terminal_handler import DEFAULT_ALLOWED_PATH_ENV, WorkspaceTerminalHandler

__all__ = [
    "ActionRequest",
    "ClientPermissionGate",
    "DEFAULT_ALLOWED_PATH_ENV",
    "FullAcpClient",
    "FullAcpSession",
    "InteractivePermissionGate",
    "PolicyPermissionGate",
    "PromptResult",
    "STOP_REASON_FINISH",
    "VALID_OPTION_KINDS",
    "WorkspaceFsHandler",
    "WorkspaceTerminalHandler",
    "is_sensitive_relpath",
    "sanitize_terminal_text",
    "validate_permission_params",
]
