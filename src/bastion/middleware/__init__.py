"""FastMCP middleware for the Bastion gateway."""

from bastion.middleware.audit_mw import AuditMiddleware
from bastion.middleware.error_mw import ErrorBoundary

__all__ = ["AuditMiddleware", "ErrorBoundary"]
