import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

def get_user_data(user_id):
    # 漏洞 1: 隐藏在辅助函数里的 SQL 注入
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM profiles WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()

@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    # 这里调用了带漏洞的函数
    data = get_user_data(user_id)
    return str(data)

@app.route("/export")
def export():
    filename = request.args.get("filename")
    # 漏洞 2: 命令注入 (Command Injection)
    # 攻击者可以输入: report.txt; rm -rf /
    cmd = f"tar -czf exports/{filename}.tar.gz /data/logs"
    subprocess.os.system(cmd)
    return "Export started"

@app.route("/debug")
def debug():
    # 漏洞 3: 危险的反序列化
    import pickle
    import base64
    config_data = request.args.get("config")
    # 攻击者可以构造恶意 pickle 对象
    config = pickle.loads(base64.b64decode(config_data))
    return "Config updated"

if __name__ == "__main__":
    app.run()
