import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cur.fetchall()


def list_tables(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    return cur.fetchall()
