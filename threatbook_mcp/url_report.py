"""微步在线威胁分析URL信誉报告模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.url_report")


class URLReportTool:
    """URL信誉报告工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="url_report",
            description="URL信誉报告：获取URL扫描引擎检测结果，以及下载文件的分析结果",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "要查询的URL地址（需要进行URL编码）"
                    }
                },
                "required": ["url"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行URL信誉报告查询"""
        try:
            url = arguments.get("url")
            if not url:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'url'"
                )]
            
            # 调用微步在线威胁分析API
            result = await self.client.get_url_report(url)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"URL信誉报告查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化URL信誉报告结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        # 威胁等级
        threat_level = result.get("threat_level", "unknown")
        threat_icons = {
            "malicious": "🚨",
            "suspicious": "⚠️",
            "clean": "✅"
        }
        threat_text = {
            "malicious": "恶意",
            "suspicious": "可疑",
            "clean": "安全"
        }
        
        icon = threat_icons.get(threat_level, "❓")
        status = threat_text.get(threat_level, "未知")
        
        output = [
            f"🔍 URL信誉报告",
            f"",
            f"{icon} 威胁等级: {status}",
        ]
        
        # 多引擎检测结果
        multiengines = result.get("multiengines", {})
        if multiengines:
            output.append("")
            output.append("🔬 多引擎检测结果:")
            
            detected_engines = []
            safe_engines = []
            
            for engine, detection in multiengines.items():
                if detection and detection.lower() not in ["safe", "whitelist"]:
                    if detection == "whitelist":
                        safe_engines.append(f"  ✅ {engine}: 白名单")
                    else:
                        detected_engines.append(f"  🔴 {engine}: {detection}")
                else:
                    safe_engines.append(f"  ✅ {engine}: 安全")
            
            if detected_engines:
                output.append("")
                output.append("检出威胁的引擎:")
                output.extend(detected_engines)
            
            if safe_engines:
                output.append("")
                output.append("安全引擎 (部分显示):")
                output.extend(safe_engines[:5])  # 只显示前5个
                if len(safe_engines) > 5:
                    output.append(f"  ... 还有 {len(safe_engines) - 5} 个引擎显示安全")
        
        # 沙箱分析结果
        sandbox = result.get("sandbox", {})
        if sandbox:
            output.append("")
            output.append("📦 下载文件沙箱分析:")
            
            file_threat_level = sandbox.get("threat_level", "")
            if file_threat_level:
                file_icon = threat_icons.get(file_threat_level, "❓")
                file_status = threat_text.get(file_threat_level, "未知")
                output.append(f"  {file_icon} 文件威胁等级: {file_status}")
            
            file_name = sandbox.get("file_name", "")
            if file_name:
                output.append(f"  📄 文件名: {file_name}")
            
            file_type = sandbox.get("file_type", "")
            if file_type:
                output.append(f"  📋 文件类型: {file_type}")
            
            sample_sha256 = sandbox.get("sample_sha256", "")
            if sample_sha256:
                output.append(f"  🔑 SHA256: {sample_sha256}")
        
        # HTTP响应详情
        details = result.get("details", {})
        if details:
            output.append("")
            output.append("🌐 HTTP响应详情:")
            
            final_url = details.get("finalUrl", "")
            if final_url:
                output.append(f"  🔗 最终URL: {final_url}")
            
            ip = details.get("ip", "")
            if ip:
                output.append(f"  📍 解析IP: {ip}")
            
            status_code = details.get("httpStatusCode", "")
            if status_code:
                output.append(f"  📊 状态码: {status_code}")
            
            last_seen = details.get("lastSeen", "")
            if last_seen:
                output.append(f"  🕐 最后扫描: {last_seen}")
        
        return "\n".join(output)
