import ast
import jedi
import os
from asttokens import ASTTokens

def get_enhanced_context(file_path, line_number):
    try:
        abs_path = os.path.abspath(file_path)
        with open(abs_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        atok = ASTTokens(source_code, parse=True)
        relevant_code = []

        # 1. 提取 Import
        imports = [atok.get_text(n) for n in ast.walk(atok.tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        if imports: relevant_code.append("# Imports\n" + "\n".join(imports))

        # 2. 提取本地函数上下文
        for node in ast.walk(atok.tree):
            if hasattr(node, 'first_token') and node.first_token.start[0] <= line_number <= node.last_token.end[0]:
                if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                    relevant_code.append(f"# Local Context Body\n{atok.get_text(node)}")
                    break

        # 3. 强力 Jedi 跨文件跳转
        script = jedi.Script(code=source_code, path=abs_path)
        # 尝试在那一行的不同位置寻找定义（通常函数名在开头）
        defs = script.goto(line=line_number, column=0) 
        
        for d in defs:
            if d.module_path and str(d.module_path) != abs_path:
                try:
                    with open(d.module_path, 'r', encoding='utf-8') as rf:
                        remote_lines = rf.readlines()
                        # 抓取定义处及其后 10 行
                        start_idx = max(0, d.line - 1)
                        end_idx = min(len(remote_lines), d.line + 10)
                        snippet = "".join(remote_lines[start_idx:end_idx])
                        relevant_code.append(f"# --- Traced External Logic in {d.module_name} ---\n{snippet}")
                except:
                    continue

        return "\n\n".join(relevant_code)
    except Exception as e:
        return f"Retrieval Error: {str(e)}"
