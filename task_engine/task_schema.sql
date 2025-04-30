-- RooCore task + event schema (idempotent)
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS tasks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT NOT NULL,
    line          INTEGER NOT NULL,
    task          TEXT NOT NULL,
    tag           TEXT,
    severity      TEXT,
    status        TEXT NOT NULL DEFAULT 'TODO',
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    fixed_at      TEXT,
    metadata_json TEXT            -- freeform additional data
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     INTEGER NOT NULL,
    timestamp   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type  TEXT NOT NULL,
    payload     TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_status  ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_events_task   ON events(task_id);
