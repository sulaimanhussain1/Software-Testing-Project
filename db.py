import os
import sqlite3
from flask import g, has_app_context

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("TESTBOARD_DB", os.path.join(BASE_DIR, "testboard.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT NOT NULL,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','qa','dev')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS test_cases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    module       TEXT NOT NULL,
    priority     TEXT NOT NULL DEFAULT 'Medium',
    steps        TEXT,
    expected     TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_to  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at  TEXT,
    due_date     TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS executions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    test_case_id INTEGER NOT NULL REFERENCES test_cases(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    actual       TEXT,
    build        TEXT,
    notes        TEXT,
    executed_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    executed_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bugs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    bug_code         TEXT UNIQUE,
    test_case_id     INTEGER REFERENCES test_cases(id) ON DELETE SET NULL,
    execution_id     INTEGER REFERENCES executions(id) ON DELETE SET NULL,
    title            TEXT NOT NULL,
    module           TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'Medium',
    status           TEXT NOT NULL DEFAULT 'New',
    steps            TEXT,
    expected         TEXT,
    actual           TEXT,
    build            TEXT,
    reported_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_to      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    fixed_at         TEXT,
    closed_at        TEXT,
    reopen_count     INTEGER NOT NULL DEFAULT 0
);

-- Timeline of everything that happens on a bug (comments, fixes, status changes)
CREATE TABLE IF NOT EXISTS bug_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    bug_id     INTEGER NOT NULL REFERENCES bugs(id) ON DELETE CASCADE,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    kind       TEXT NOT NULL,   -- reported|assigned|started|fixed|closed|reopened|comment
    body       TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    bug_id        INTEGER REFERENCES bugs(id) ON DELETE CASCADE,
    event_id      INTEGER REFERENCES bug_events(id) ON DELETE CASCADE,
    execution_id  INTEGER REFERENCES executions(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name   TEXT NOT NULL UNIQUE,
    mime          TEXT,
    size          INTEGER NOT NULL DEFAULT 0,
    uploaded_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message    TEXT NOT NULL,
    link       TEXT,
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bugs_assigned  ON bugs(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_bugs_status    ON bugs(status);
CREATE INDEX IF NOT EXISTS idx_tc_assigned    ON test_cases(assigned_to);
CREATE INDEX IF NOT EXISTS idx_exec_tc        ON executions(test_case_id);
CREATE INDEX IF NOT EXISTS idx_events_bug     ON bug_events(bug_id);
CREATE INDEX IF NOT EXISTS idx_notif_user     ON notifications(user_id, is_read);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if has_app_context():
        if "db" not in g:
            g.db = connect()
        return g.db
    raise RuntimeError("get_db() needs an app context; use connect() instead")


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    conn = get_db()
    cur = conn.execute(sql, args)
    conn.commit()
    return cur.lastrowid
