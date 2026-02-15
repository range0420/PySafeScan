import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    # 典型的 SSRF 漏洞
    target_url = request.args.get("url")
    return requests.get(target_url).text
