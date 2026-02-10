#!/usr/bin/env python3
"""验证修复方案"""

import ast
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

# 临时修复方案
class QuickFixAnalyzer:
    def __init__(self):
        self.tainted_vars = set()
        self.vulnerabilities = []
        
    def analyze(self, code):
        tree = ast.parse(code)
        
        # 处理直接调用
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # 获取函数名
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    
                    # 如果是input()
                    if func_name == 'input':
                        # 检查父节点
                        parent = getattr(node, 'parent', None)
                        
                        if isinstance(parent, ast.Expr):
                            # 直接调用，检查父父节点
                            parent_parent = getattr(parent, 'parent', None)
                            if isinstance(parent_parent, ast.Call):
                                # 如 eval(input(...))
                                self.vulnerabilities.append(f"直接调用漏洞在第{node.lineno}行")
        
        return {
            'vulnerabilities': self.vulnerabilities,
            'tainted': list(self.tainted_vars)
        }

# 测试失败的案例
test2_code = 'eval(input("代码: "))'
test4_code = '''
cmd = input("命令: ")
clean_cmd = cmd.strip()
os.system(clean_cmd)
'''

print("测试2: 直接调用")
analyzer = QuickFixAnalyzer()
result = analyzer.analyze(test2_code)
print(f"发现漏洞: {len(result['vulnerabilities'])}")
for vuln in result['vulnerabilities']:
    print(f"  - {vuln}")

print("\n测试4: 字符串操作传播")
# 这需要完整的分析器，我们直接手动分析
print("手动分析 test4_code:")
print("1. cmd = input(...)  # cmd被标记为污点")
print("2. clean_cmd = cmd.strip()  # clean_cmd应该被传播污点")
print("3. os.system(clean_cmd)  # 应该检测到漏洞")
print("问题可能是: strip()传播后，clean_cmd没有被正确追踪")
