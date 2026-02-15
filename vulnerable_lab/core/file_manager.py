import os

class DataProcessor:
    def __init__(self, base_path="/var/data"):
        self.base = base_path

    def read_user_file(self, filename):
        # 典型的路径穿越漏洞
        target_path = os.path.join(self.base, filename)
        with open(target_path, 'r') as f:
            return f.read()
