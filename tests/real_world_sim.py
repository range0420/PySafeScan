import os

class FileProcessor:
    def __init__(self, root="/tmp/data"):
        self.root = root

    def process_user_file(self, filename):
        # 故意留下路径穿越漏洞，且在类方法中（有 self 缩进）
        target = os.path.join(self.root, filename)
        with open(target, 'r') as f:
            return f.read()

def legacy_request():
    # 模拟没有缩进的全局 SSRF
    import requests
    url = "http://example.com/api"
    return requests.get(url).content
