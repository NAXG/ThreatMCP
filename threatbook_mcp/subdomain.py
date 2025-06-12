"""微步在线威胁分析子域名查询模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.subdomain")


class SubdomainTool:
    """子域名查询工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="subdomain",
            description="子域名查询：获取域名的所有子域名信息，用于资产发现和安全评估",
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
        """执行子域名查询"""
        try:
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'domain'"
                )]
            
            lang = arguments.get("lang", "zh")
            
            # 调用微步在线威胁分析API
            result = await self.client.get_subdomain(domain, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"子域名查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化子域名查询结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        domain = result.get("domain", "")
        if not domain:
            return "❌ 未找到域名信息"
        
        output = [
            f"🔍 子域名查询结果",
            f"",
            f"🌐 主域名: {domain}",
            f""
        ]
        
        # 子域名信息
        sub_domains = result.get("sub_domains", {})
        if sub_domains:
            total = sub_domains.get("total", "0")
            data = sub_domains.get("data", [])
            
            output.append(f"📊 子域名统计:")
            output.append(f"  • 总数量: {total}")
            output.append(f"  • 本次返回: {len(data) if data else 0}")
            output.append("")
            
            if data:
                output.append("📋 子域名列表:")
                
                # 按字母顺序排序
                sorted_subdomains = sorted(data) if isinstance(data, list) else []
                
                # 分类显示子域名
                www_domains = []
                mail_domains = []
                api_domains = []
                other_domains = []
                
                for subdomain in sorted_subdomains:
                    if subdomain.startswith("www."):
                        www_domains.append(subdomain)
                    elif any(prefix in subdomain.lower() for prefix in ["mail", "mx", "smtp", "pop", "imap"]):
                        mail_domains.append(subdomain)
                    elif any(prefix in subdomain.lower() for prefix in ["api", "rest", "service", "endpoint"]):
                        api_domains.append(subdomain)
                    else:
                        other_domains.append(subdomain)
                
                # 显示分类结果
                if www_domains:
                    output.append("  🌐 Web服务:")
                    for subdomain in www_domains[:10]:  # 只显示前10个
                        output.append(f"    • {subdomain}")
                    if len(www_domains) > 10:
                        output.append(f"    • ... 还有 {len(www_domains) - 10} 个")
                    output.append("")
                
                if mail_domains:
                    output.append("  📧 邮件服务:")
                    for subdomain in mail_domains[:5]:  # 只显示前5个
                        output.append(f"    • {subdomain}")
                    if len(mail_domains) > 5:
                        output.append(f"    • ... 还有 {len(mail_domains) - 5} 个")
                    output.append("")
                
                if api_domains:
                    output.append("  🔌 API服务:")
                    for subdomain in api_domains[:10]:  # 只显示前10个
                        output.append(f"    • {subdomain}")
                    if len(api_domains) > 10:
                        output.append(f"    • ... 还有 {len(api_domains) - 10} 个")
                    output.append("")
                
                if other_domains:
                    output.append("  🔧 其他服务:")
                    # 根据总数量决定显示多少个
                    display_count = min(20, len(other_domains))
                    
                    for subdomain in other_domains[:display_count]:
                        output.append(f"    • {subdomain}")
                    
                    if len(other_domains) > display_count:
                        output.append(f"    • ... 还有 {len(other_domains) - display_count} 个")
                    output.append("")
                
                # 安全建议
                if len(sorted_subdomains) > 50:
                    output.append("⚠️ 安全提醒:")
                    output.append("  • 子域名数量较多，建议定期检查是否存在未使用的子域名")
                    output.append("  • 确保所有子域名都有适当的安全配置")
                    output.append("  • 考虑使用子域名监控工具")
                    output.append("")
            
        else:
            output.append("ℹ️ 未找到子域名信息")
        
        # 详细报告链接
        permalink = result.get("permalink", "")
        if permalink:
            output.append(f"📋 详细报告: {permalink}")
        
        return "\n".join(output) 