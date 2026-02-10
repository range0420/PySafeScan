"""
污点分析引擎 - 完整实现（无外部依赖）
全国信息安全竞赛核心模块
"""

import ast
import json
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

class TaintType(Enum):
    """污点类型枚举"""
    USER_INPUT = "user_input"
    COMMAND_LINE = "command_line"
    WEB_INPUT = "web_input"
    ENVIRONMENT = "environment"
    FILE_INPUT = "file_input"
    NETWORK = "network"
    PROPAGATED = "propagated"
    PARAMETER = "parameter"

@dataclass
class TaintVariable:
    """污点变量"""
    name: str
    line: int
    type: TaintType
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            'name': self.name,
            'line': self.line,
            'type': self.type.value,
            'sources': self.sources
        }

class TaintAnalyzer(ast.NodeVisitor):
    """污点分析器 - 核心算法实现"""
    
    def __init__(self):
        super().__init__()
        
        # 污点源定义（函数名）
        self.source_patterns = {
            'input': TaintType.USER_INPUT,
            'raw_input': TaintType.USER_INPUT,
            'argv': TaintType.COMMAND_LINE,
            'get': TaintType.WEB_INPUT,
            'post': TaintType.WEB_INPUT,
            'request': TaintType.WEB_INPUT,
            'environ': TaintType.ENVIRONMENT,
            'getenv': TaintType.ENVIRONMENT,
            'read': TaintType.FILE_INPUT,
            'recv': TaintType.NETWORK,
        }
        
        # 危险函数（污点汇聚点）
        self.sink_patterns = {
            'os.system': 'command_injection',
            'os.popen': 'command_injection',
            'subprocess.call': 'command_injection',
            'subprocess.Popen': 'command_injection',
            'subprocess.run': 'command_injection',
            'eval': 'code_injection',
            'exec': 'code_injection',
            'compile': 'code_injection',
            '__import__': 'code_injection',
            'pickle.loads': 'deserialization',
            'yaml.load': 'deserialization',
            'marshal.loads': 'deserialization',
            'open': 'path_traversal',
            'execfile': 'code_injection',
        }
        
        # 传播函数
        self.propagator_patterns = {
            'format', 'replace', 'strip', 'split', 'join',
            'upper', 'lower', 'encode', 'decode', 'capitalize',
            'title', 'swapcase', 'lstrip', 'rstrip',
        }
        
        # 分析状态
        self.tainted_vars: Dict[str, TaintVariable] = {}
        self.vulnerability_paths: List[List[str]] = []
        self.propagation_graph: Dict[str, List[str]] = {}
        self.current_file = ""
        
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """分析文件"""
        self.current_file = filepath
        self._reset_state()
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
            
            tree = ast.parse(code)
            self.visit(tree)
            
            return self._generate_report()
            
        except Exception as e:
            print(f"[ERROR] 污点分析失败 {filepath}: {e}")
            return {}
    
    def analyze_code(self, code: str, filename: str = "<string>") -> Dict[str, Any]:
        """分析代码字符串"""
        self.current_file = filename
        self._reset_state()
        
        try:
            tree = ast.parse(code)
            self.visit(tree)
            return self._generate_report()
        except Exception as e:
            print(f"[ERROR] 污点分析失败: {e}")
            return {}
    
    def visit_Call(self, node: ast.Call):
        """分析函数调用"""
        func_name = self._extract_function_name(node.func)
        
        # 检查是否是污点源
        taint_type = self._get_taint_type(func_name)
        if taint_type:
            self._handle_taint_source(node, func_name, taint_type)
        
        # 检查是否是危险函数
        vuln_type = self._get_vulnerability_type(func_name)
        if vuln_type:
            self._handle_taint_sink(node, func_name, vuln_type)
        
        # 检查是否是传播函数
        if self._is_propagator(func_name):
            self._handle_propagator(node, func_name)
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """分析赋值语句"""
        tainted_sources = self._find_tainted_variables(node.value)
        
        if tainted_sources:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self._create_or_update_tainted_var(
                        var_name, node.lineno, TaintType.PROPAGATED, tainted_sources
                    )
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """分析函数定义 - 参数标记为可能污点"""
        for arg in node.args.args:
            var_name = arg.arg
            if var_name not in self.tainted_vars:
                self.tainted_vars[var_name] = TaintVariable(
                    var_name, node.lineno, TaintType.PARAMETER
                )
        
        self.generic_visit(node)
    
    def _extract_function_name(self, node) -> str:
        """提取函数名"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # 处理 os.system 形式
            return self._extract_attribute_name(node)
        return ""
    
    def _extract_attribute_name(self, node: ast.Attribute) -> str:
        """提取属性访问名称"""
        parts = []
        current = node
        
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        
        if isinstance(current, ast.Name):
            parts.append(current.id)
        
        parts.reverse()
        return ".".join(parts)
    
    def _get_taint_type(self, func_name: str) -> Optional[TaintType]:
        """获取污点类型"""
        for pattern, taint_type in self.source_patterns.items():
            if pattern in func_name:
                return taint_type
        return None
    
    def _get_vulnerability_type(self, func_name: str) -> Optional[str]:
        """获取漏洞类型"""
        for pattern, vuln_type in self.sink_patterns.items():
            if pattern in func_name:
                return vuln_type
        return None
    
    def _is_propagator(self, func_name: str) -> bool:
        """检查是否是传播函数"""
        # 提取基本函数名（移除模块前缀）
        base_name = func_name.split('.')[-1]
        return base_name in self.propagator_patterns
    
    def _handle_taint_source(self, node: ast.Call, func_name: str, taint_type: TaintType):
        """处理污点源"""
        # 检查是否有赋值
        parent = getattr(node, 'parent', None)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted_vars[var_name] = TaintVariable(
                        var_name, node.lineno, taint_type
                    )
                    print(f"[SOURCE] {var_name} ← {func_name} ({taint_type.value})")
    
    def _handle_taint_sink(self, node: ast.Call, func_name: str, vuln_type: str):
        """处理污点汇聚点"""
        # 检查参数是否包含污点变量
        tainted_args = []
        for arg in node.args:
            tainted_args.extend(self._find_tainted_variables(arg))
        
        for tainted_var in tainted_args:
            # 查找污点路径
            path = self._trace_taint_path(tainted_var)
            if path:
                path.append(f"{func_name}()")
                self.vulnerability_paths.append(path)
                
                print(f"[VULNERABILITY] {vuln_type.upper()} 在行 {node.lineno}")
                print(f"  路径: {' → '.join(path)}")
    
    def _handle_propagator(self, node: ast.Call, func_name: str):
        """处理传播函数"""
        # 检查输入参数是否污点
        tainted_inputs = []
        for arg in node.args:
            tainted_inputs.extend(self._find_tainted_variables(arg))
        
        if tainted_inputs:
            parent = getattr(node, 'parent', None)
            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        output_var = target.id
                        self._create_or_update_tainted_var(
                            output_var, node.lineno, TaintType.PROPAGATED, tainted_inputs
                        )
    
    def _find_tainted_variables(self, node: ast.AST) -> List[str]:
        """在表达式中查找污点变量"""
        tainted = []
        
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                tainted.append(node.id)
        
        elif isinstance(node, ast.BinOp):
            tainted.extend(self._find_tainted_variables(node.left))
            tainted.extend(self._find_tainted_variables(node.right))
        
        elif isinstance(node, ast.Call):
            for arg in node.args:
                tainted.extend(self._find_tainted_variables(arg))
        
        return list(set(tainted))  # 去重
    
    def _create_or_update_tainted_var(self, var_name: str, line: int, 
                                     taint_type: TaintType, sources: List[str]):
        """创建或更新污点变量"""
        if var_name not in self.tainted_vars:
            self.tainted_vars[var_name] = TaintVariable(var_name, line, taint_type)
        
        # 添加来源关系
        for source in sources:
            if source in self.tainted_vars and source not in self.tainted_vars[var_name].sources:
                self.tainted_vars[var_name].sources.append(source)
                
                # 添加到传播图
                if source not in self.propagation_graph:
                    self.propagation_graph[source] = []
                if var_name not in self.propagation_graph[source]:
                    self.propagation_graph[source].append(var_name)
    
    def _trace_taint_path(self, start_var: str) -> List[str]:
        """追踪污点路径"""
        path = [start_var]
        current = start_var
        
        # 反向追踪到源头
        while current in self.tainted_vars:
            var = self.tainted_vars[current]
            if var.sources:
                # 取第一个来源继续追踪
                current = var.sources[0]
                if current not in path:  # 避免循环
                    path.insert(0, current)
                else:
                    break
            else:
                break
        
        return path
    
    def _generate_report(self) -> Dict[str, Any]:
        """生成分析报告"""
        sources_found = []
        for var_name, var in self.tainted_vars.items():
            if var.type in [TaintType.USER_INPUT, TaintType.COMMAND_LINE, 
                           TaintType.WEB_INPUT, TaintType.FILE_INPUT]:
                sources_found.append(var.to_dict())
        
        # 构建图边列表
        graph_edges = []
        for source, targets in self.propagation_graph.items():
            for target in targets:
                graph_edges.append([source, target])
        
        return {
            'file': self.current_file,
            'tainted_variables': len(self.tainted_vars),
            'vulnerability_paths': self.vulnerability_paths,
            'graph_edges': graph_edges,
            'analysis_details': {
                'sources_found': sources_found,
                'sinks_found': len(self.vulnerability_paths),
                'propagation_chains': self._extract_propagation_chains()
            }
        }
    
    def _extract_propagation_chains(self) -> List[List[str]]:
        """提取完整的传播链"""
        chains = []
        visited = set()
        
        def dfs(current: str, path: List[str]):
            if current in visited:
                return
            
            visited.add(current)
            path.append(current)
            
            # 如果当前变量没有后续传播，且路径长度>1，则是一条完整链
            if current not in self.propagation_graph or not self.propagation_graph[current]:
                if len(path) > 1:
                    chains.append(path.copy())
            else:
                for next_var in self.propagation_graph[current]:
                    dfs(next_var, path)
            
            path.pop()
        
        # 从每个可能的起点开始
        for var_name in self.tainted_vars:
            if not self._has_incoming_edges(var_name):
                dfs(var_name, [])
        
        return chains
    
    def _has_incoming_edges(self, var_name: str) -> bool:
        """检查变量是否有入边"""
        for _, targets in self.propagation_graph.items():
            if var_name in targets:
                return True
        return False
    
    def _reset_state(self):
        """重置分析状态"""
        self.tainted_vars.clear()
        self.vulnerability_paths.clear()
        self.propagation_graph.clear()

class AdvancedTaintTracker:
    """高级污点追踪器 - 支持项目级分析"""
    
    def __init__(self):
        self.analyzers = {}
        
    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """分析整个项目"""
        import os
        
        results = {}
        
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    analyzer = TaintAnalyzer()
                    result = analyzer.analyze_file(filepath)
                    if result:  # 只添加非空结果
                        results[filepath] = result
        
        return {
            'per_file_results': results,
            'summary': self._generate_project_summary(results)
        }
    
    def _generate_project_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成项目摘要"""
        total_vulns = 0
        files_with_vulns = 0
        vuln_types = {}
        
        for file_result in results.values():
            vuln_count = len(file_result.get('vulnerability_paths', []))
            total_vulns += vuln_count
            
            if vuln_count > 0:
                files_with_vulns += 1
            
            # 统计漏洞类型（简化版）
            for path in file_result.get('vulnerability_paths', []):
                sink = path[-1] if path else ''
                if 'system' in sink or 'subprocess' in sink:
                    vuln_types['command_injection'] = vuln_types.get('command_injection', 0) + 1
                elif 'eval' in sink or 'exec' in sink:
                    vuln_types['code_injection'] = vuln_types.get('code_injection', 0) + 1
                elif 'load' in sink:
                    vuln_types['deserialization'] = vuln_types.get('deserialization', 0) + 1
                elif 'open' in sink:
                    vuln_types['path_traversal'] = vuln_types.get('path_traversal', 0) + 1
        
        return {
            'total_files': len(results),
            'total_vulnerabilities': total_vulns,
            'files_with_vulns': files_with_vulns,
            'vulnerability_types': vuln_types
        }
