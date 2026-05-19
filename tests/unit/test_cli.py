from typer.testing import CliRunner

from bastion import __version__
from bastion.cli import app

runner = CliRunner()


def test_root_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output == f"bastion {__version__}\n"


def test_version_command_prints_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output == f"bastion {__version__}\n"
