import sqlite3

def run_query(conn, query_str):
    # 这是真正的 Sink 点
    cursor = conn.cursor()
    cursor.execute(query_str)
