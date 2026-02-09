import ast
from asttokens import ASTTokens

def get_enhanced_context(file_path, line_number):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        atok = ASTTokens(source_code, parse=True)
        relevant_code = []
        # 1. 提取所有 Import
        imports = [atok.get_text(n) for n in ast.walk(atok.tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        if imports: relevant_code.append("# Imports\n" + "\n".join(imports))
        # 2. 提取最外层包含该行的类或函数
        target_node = None
        for node in ast.walk(atok.tree):
            if hasattr(node, 'first_token'):
                if node.first_token.start[0] <= line_number <= node.last_token.end[0]:
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                        target_node = node
        if target_node:
            relevant_code.append(f"# Context Body\n{atok.get_text(target_node)}")
        return "\n\n".join(relevant_code)
    except:
        return "Context not found."
