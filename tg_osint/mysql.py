from __future__ import annotations

import os
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor


def connection_kwargs() -> dict:
    return {
        "host": os.getenv("TELEGRAM_OSINT_DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("TELEGRAM_OSINT_DB_PORT", "3306")),
        "user": os.getenv("TELEGRAM_OSINT_DB_USER", "root"),
        "password": os.getenv("TELEGRAM_OSINT_DB_PASSWORD", ""),
        "database": os.getenv("TELEGRAM_OSINT_DB_NAME", "telegram_osint"),
        "charset": "utf8mb4",
        "cursorclass": DictCursor,
        "autocommit": False,
    }


def ensure_database() -> None:
    cfg = connection_kwargs()
    database = cfg.pop("database")
    conn = pymysql.connect(**cfg)
    try:
        with conn.cursor() as cur:
            safe = database.replace(chr(96), chr(96) + chr(96))
            cur.execute("CREATE DATABASE IF NOT EXISTS " + chr(96) + safe + chr(96) + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()


def connect():
    ensure_database()
    return pymysql.connect(**connection_kwargs())


@contextmanager
def transaction(conn):
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
