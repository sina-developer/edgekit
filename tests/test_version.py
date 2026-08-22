"""The published version must stay a SemVer string recorded in CHANGELOG.md."""

from __future__ import annotations

import re
from pathlib import Path

from edgekit import __version__

REPO = Path(__file__).resolve().parents[1]


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), __version__


def test_changelog_records_the_current_version():
    changelog = (REPO / "CHANGELOG.md").read_text()
    assert f"## [{__version__}]" in changelog
