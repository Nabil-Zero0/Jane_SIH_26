"""Unit test verifying that database test isolation guard raises RuntimeError when attempting to open production DB."""

import os
from pathlib import Path
import tempfile
import unittest

from jane.db.database import get_db_connection, init_db, DEFAULT_DB_PATH


class TestIsolationGuard(unittest.TestCase):
    def test_guard_blocks_production_db_access_in_tests(self):
        # Ensure JANE_DB_PATH is cleared so it defaults to DEFAULT_DB_PATH
        prev = os.environ.pop("JANE_DB_PATH", None)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                get_db_connection(DEFAULT_DB_PATH)
            self.assertIn("TEST ISOLATION VIOLATION", str(ctx.exception))
        finally:
            if prev is not None:
                os.environ["JANE_DB_PATH"] = prev

    def test_temp_db_path_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            temp_db = Path(td) / "temp.db"
            conn = get_db_connection(temp_db)
            conn.close()
            self.assertTrue(temp_db.exists())


if __name__ == "__main__":
    unittest.main()
