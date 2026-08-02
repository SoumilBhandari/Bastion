"""Local web dashboard for the Bastion audit log."""

from bastion.dashboard.app import build_dashboard_app, new_token, run_dashboard

__all__ = ["build_dashboard_app", "new_token", "run_dashboard"]
