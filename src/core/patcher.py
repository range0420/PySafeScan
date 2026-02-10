import os

def apply_fix(file_path, line_num, old_code, new_code, full_context=None, is_block_fix=False):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 如果是块修复
    if is_block_fix and full_context:
        # 1. 清理 full_context 中的 AI 注入标签 (比如 # Local Context Body 等)
        # 我们只取函数定义开始到结束的部分
        lines_context = [l for l in full_context.splitlines() if not l.startswith('#')]
        actual_context = "\n".join(lines_context).strip()
        
        # 2. 尝试全文替换
        if actual_context in content:
            new_content = content.replace(actual_context, new_code.strip())
        else:
            # 3. 备选方案：如果 full_context 匹配失败，说明 context 里的描述太多了
            # 我们直接以 line_num 为中心，向上向下扫描函数块进行替换
            # 或者简单点：既然是重构，我们直接把 old_code 这一行及其紧邻的上下文替换
            lines = content.splitlines()
            # 这里的逻辑是：既然要重构，我们要找的是从这一行往上数，直到看到 def 的位置
            start_line = line_num - 1
            while start_line > 0 and not lines[start_line].strip().startswith('def '):
                start_line -= 1
            
            # 找到函数结束（简单的启发式：直到下一个 def 或文件末尾）
            end_line = line_num
            while end_line < len(lines) and not lines[end_line].strip().startswith('def '):
                end_line += 1
            
            # 替换整个切片
            lines[start_line:end_line] = [new_code]
            new_content = "\n".join(lines)
    else:
        # 单行替换
        lines = content.splitlines()
        lines[line_num - 1] = new_code
        new_content = "\n".join(lines)

    target_path = f"{file_path}.fixed"
    with open(target_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    return target_path
