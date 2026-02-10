import sqlite3
from db_utils import run_query

def handle_request(user_input):
    conn = sqlite3.connect("app.db")
    # 这里的 user_input 是 Source
    sql = f"SELECT * FROM users WHERE id = {user_input}"
    run_query(conn, sql)
