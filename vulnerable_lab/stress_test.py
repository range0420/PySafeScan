import os
import subprocess
from functools import wraps

def logger(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        print(f"Calling {f.__name__}")
        return f(*args, **kwargs)
    return wrapper

class UltimateTester:
    def __init__(self, root="/tmp"):
        self.root = root

    @logger
    @logger # 双重装饰器测试
    def complex_method(self, user_input, file_name):
        # 1. 第一个漏洞：命令注入
        os.system("ls " + user_input)
        
        # 2. 第二个漏洞：路径穿越 (在同一个函数内)
        path = self.root + "/" + file_name
        with open(path, 'r') as f:
            # 3. 第三个漏洞：潜在的 eval 风险（故意增加难度）
            data = f.read()
            return eval(data) 

def nested_vulnerability(data):
    def inner_sink(cmd):
        # 嵌套函数内的漏洞
        subprocess.Popen(cmd, shell=True)
    
    inner_sink("echo " + data)
