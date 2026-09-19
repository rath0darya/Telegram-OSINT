import os
import unittest
import uuid

import pymysql

from tg_osint.core import Evidence, sha256_text
from tg_osint.intel_db import IntelligenceDB


class IntelligenceDBTests(unittest.TestCase):
    def setUp(self):
        self.db_name = "telegram_osint_test_" + uuid.uuid4().hex[:12]
        os.environ["TELEGRAM_OSINT_DB_NAME"] = self.db_name

    def tearDown(self):
        os.environ.pop("TELEGRAM_OSINT_DB_NAME", None)
        conn = pymysql.connect(
            host=os.getenv("TELEGRAM_OSINT_DB_HOST", "127.0.0.1"),
            port=int(os.getenv("TELEGRAM_OSINT_DB_PORT", "3306")),
            user=os.getenv("TELEGRAM_OSINT_DB_USER", "root"),
            password=os.getenv("TELEGRAM_OSINT_DB_PASSWORD", ""),
            charset="utf8mb4",
            autocommit=True,
        )
        try:
            with conn.cursor() as cur:
                safe = self.db_name.replace("`", "``")
                cur.execute("DROP DATABASE IF EXISTS `" + safe + "`")
        finally:
            conn.close()

