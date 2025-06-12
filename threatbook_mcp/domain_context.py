"""微步在线威胁分析域名上下文查询模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.domain_context")


class DomainContextTool:
    """域名上下文查询工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="domain_context",
            description="域名上下文查询：针对恶意域名查询上下文信息，获取相关样本及取证处置建议",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "要查询的域名"
                    },
                    "lang": {
                        "type": "string",
                        "description": "返回结果语言，zh为中文，en为英文",
                        "enum": ["zh", "en"],
                        "default": "zh"
                    }
                },
                "required": ["domain"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行域名上下文查询"""
        try:
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'domain'"
                )]
            
            lang = arguments.get("lang", "zh")
            
            # 调用微步在线威胁分析API
            result = await self.client.get_domain_context(domain, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"域名上下文查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化域名上下文查询结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        resource = result.get("resource", {})
        if not resource:
            return "❌ 未找到域名信息"
        
        domain = list(resource.keys())[0]
        domain_data = resource[domain]
        
        output = [
            f"🔍 域名上下文查询结果",
            f"",
            f"🌐 域名: {domain}",
            f""
        ]
        
        # IOC上下文信息
        context = domain_data.get("context", [])
        if context:
            output.append("📋 IOC上下文信息:")
            sample_count = len(context)
            output.append(f"  • 相关样本数量: {sample_count}")
            
            # 显示前几个样本
            for i, ctx in enumerate(context[:5]):
                sample = ctx.get("sample", "")
                if sample:
                    output.append(f"  • 样本 {i+1}: {sample}")
            
            if sample_count > 5:
                output.append(f"  • ... 还有 {sample_count - 5} 个样本")
            output.append("")
        
        # 取证及处置建议
        forensics = domain_data.get("forensics", [])
        if forensics:
            output.append("🔍 取证及处置建议:")
            output.append("")
            
            for i, forensic in enumerate(forensics[:3]):  # 只显示前3个
                sample_info = forensic.get("sample", {})
                suggestion = forensic.get("suggestion", {})
                
                if sample_info:
                    output.append(f"  📄 样本 {i+1}:")
                    
                    sha256 = sample_info.get("sha256", "")
                    if sha256:
                        output.append(f"    • SHA256: {sha256}")
                    
                    file_type = sample_info.get("file_type", "")
                    if file_type:
                        output.append(f"    • 文件类型: {file_type}")
                    
                    malware_family = sample_info.get("malware_family", "")
                    if malware_family:
                        output.append(f"    • 恶意家族: {malware_family}")
                    
                    malware_type = sample_info.get("malware_type", "")
                    if malware_type:
                        output.append(f"    • 恶意类型: {malware_type}")
                    
                    threat_level = sample_info.get("threat_level", "")
                    if threat_level:
                        threat_icons = {
                            "malicious": "🔴",
                            "suspicious": "🟡",
                            "clean": "✅"
                        }
                        icon = threat_icons.get(threat_level, "⚠️")
                        output.append(f"    • {icon} 威胁等级: {threat_level}")
                    
                    tags = sample_info.get("tag", [])
                    if tags:
                        output.append(f"    • 标签: {', '.join(tags)}")
                    
                    # 相关域名
                    domains = sample_info.get("domains", [])
                    if domains:
                        output.append(f"    • 相关域名:")
                        for domain_info in domains[:3]:
                            domain_name = domain_info.get("domain", "")
                            ip = domain_info.get("ip", "")
                            if domain_name:
                                if ip:
                                    output.append(f"      - {domain_name} -> {ip}")
                                else:
                                    output.append(f"      - {domain_name}")
                
                # 处置建议
                if suggestion:
                    output.append(f"    💡 处置建议:")
                    for key, value in suggestion.items():
                        if value:
                            output.append(f"      • {key}: {value}")
                
                output.append("")
        
        # 详细报告链接
        permalink = domain_data.get("permalink", "")
        if permalink:
            output.append(f"📋 详细报告: {permalink}")
        
        # 如果没有任何有用信息
        if not context and not forensics:
            output.append("ℹ️ 未找到相关上下文信息")
        
        return "\n".join(output) 