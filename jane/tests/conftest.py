import os
from pathlib import Path
import tempfile
import pytest

from jane.db import database


import gc
import sys

@pytest.fixture(autouse=True)
def isolate_database(monkeypatch):
    """Automatically isolate every pytest test into its own temporary database."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        temp_db = Path(td) / "test_session_jane.db"
        monkeypatch.setenv("JANE_DB_PATH", str(temp_db))
        monkeypatch.setattr(database, "DB_PATH", temp_db)
        database.init_db(temp_db)
        yield temp_db
        gc.collect()
