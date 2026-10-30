def run_search(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()
