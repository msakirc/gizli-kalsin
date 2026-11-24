import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redact_guard.engine import Redactor  # noqa: E402
from redact_guard.vault import Vault  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def redactor():
    return Redactor(Vault(os.urandom(48)))


@pytest.fixture
def fixtures():
    return {p.name: p.read_text() for p in FIXTURES.iterdir() if p.is_file()}
