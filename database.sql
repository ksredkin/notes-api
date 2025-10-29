CREATE TABLE IF NOT EXISTS notes (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" INTEGER NOT NULL,
    "name" TEXT,
    "text" TEXT,
    "date" TIMESTAMPTZ,
    UNIQUE("user_id", "name")
);
CREATE TABLE IF NOT EXISTS users (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "username" TEXT,
    "password" TEXT
)