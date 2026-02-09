import json
import datetime

def generate_report(results, output_file="report.html"):
    # 注意：CSS中的 { 变成了 {{， } 变成了 }}
    html_template = """
    <html>
    <head>
        <title>PySafeScan AI 审计报告</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f7f6; }}
            .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .stat-box {{ display: flex; gap: 20px; margin-bottom: 30px; }}
            .stat-card {{ padding: 20px; border-radius: 5px; color: white; flex: 1; text-align: center; font-weight: bold; }}
            .high {{ background-color: #e74c3c; }}
            .medium {{ background-color: #f39c12; }}
            .low {{ background-color: #27ae60; }}
            .issue-card {{ border: 1px solid #ddd; margin-bottom: 20px; padding: 15px; border-radius: 5px; border-left: 8px solid; }}
            .code-block {{ background: #2d3436; color: #fab1a0; padding: 10px; border-radius: 4px; font-family: 'Courier New', monospace; overflow-x: auto; }}
            .suggestion {{ color: #2980b9; font-style: italic; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ PySafeScan 安全扫描报告</h1>
            <p>生成时间: {timestamp}</p>
            <div class="stat-box">
                <div class="stat-card high">高风险: {high_count}</div>
                <div class="stat-card medium">中/低风险: {low_count}</div>
            </div>
            {content}
        </div>
    </body>
    </html>
    """
    
    content = ""
    high_count = 0
    low_count = 0
    
    for r in results:
        risk = r.get('risk_level', 'low').lower()
        if risk == 'high': high_count += 1
        else: low_count += 1
        
        color_class = "high" if risk == "high" else "low"
        content += f"""
        <div class="issue-card" style="border-left-color: {'#e74c3c' if risk == 'high' else '#27ae60'}">
            <h3>[{r.get('vulnerability', 'Other')}] 在 {r.get('file')}:{r.get('line')}</h3>
            <div class="code-block"><code>{r.get('api')}</code></div>
            <p class="suggestion"><strong>建议:</strong> {r.get('suggestion')}</p>
        </div>
        """
    
    full_html = html_template.format(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        high_count=high_count,
        low_count=low_count,
        content=content
    )
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"✨ 报告已生成: {output_file}")
