"""Audit logging for the Bastion gateway."""

from bastion.audit.record import AuditRecord
from bastion.audit.writer import AuditWriter

__all__ = ["AuditRecord", "AuditWriter"]
