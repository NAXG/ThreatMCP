"""微步在线威胁分析域名高级查询模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.domain_advanced")


class DomainAdvancedTool:
    """域名高级查询工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="domain_advanced",
            description="域名高级查询：获取域名的历史IP和历史Whois信息，用于深度溯源分析",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "要查询的域名"
                    },
                    "exclude": {
                        "type": "string",
                        "description": "可排除的字段，多个用逗号分隔：history_ips,history_whoises"
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
        """执行域名高级查询"""
        try:
            domain = arguments.get("domain")
            if not domain:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'domain'"
                )]
            
            exclude = arguments.get("exclude", "")
            lang = arguments.get("lang", "zh")
            
            # 调用微步在线威胁分析API
            result = await self.client.get_domain_advanced(domain, exclude, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"域名高级查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化域名高级查询结果"""
        
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
            f"🔍 域名高级查询结果",
            f"",
            f"🌐 域名: {domain}",
            f""
        ]
        
        # 历史IP信息
        history_ips = result.get("history_ips", [])
        if history_ips:
            output.append("📅 历史解析IP记录:")
            
            for i, ip_record in enumerate(history_ips[:10]):  # 只显示前10个记录
                date = ip_record.get("date", "")
                ips = ip_record.get("ips", [])
                
                output.append(f"  📅 {date}:")
                
                if isinstance(ips, list):
                    for ip_info in ips[:5]:  # 每个日期只显示前5个IP
                        ip = ip_info.get("ip", "")
                        carrier = ip_info.get("carrier", "")
                        location = ip_info.get("location", {})
                        
                        ip_desc = f"    • {ip}"
                        
                        if location:
                            country = location.get("country", "")
                            province = location.get("province", "")
                            city = location.get("city", "")
                            
                            location_str = country
                            if province:
                                location_str += f" {province}"
                            if city:
                                location_str += f" {city}"
                            
                            if location_str:
                                ip_desc += f" ({location_str})"
                        
                        if carrier:
                            ip_desc += f" - {carrier}"
                        
                        output.append(ip_desc)
                    
                    if len(ips) > 5:
                        output.append(f"    • ... 还有 {len(ips) - 5} 个IP")
                
                output.append("")
            
            if len(history_ips) > 10:
                output.append(f"  📈 还有 {len(history_ips) - 10} 个历史记录")
                output.append("")
        
        # 历史Whois信息
        history_whoises = result.get("history_whoises", [])
        if history_whoises:
            output.append("📋 历史Whois记录:")
            
            for i, whois_record in enumerate(history_whoises[:5]):  # 只显示前5个记录
                date = whois_record.get("date", "")
                whois = whois_record.get("whois", {})
                
                output.append(f"  📅 {date}:")
                
                if whois:
                    registrar_name = whois.get("registrar_name", "")
                    if registrar_name:
                        output.append(f"    • 注册商: {registrar_name}")
                    
                    registrant_name = whois.get("registrant_name", "")
                    if registrant_name:
                        output.append(f"    • 注册者: {registrant_name}")
                    
                    registrant_company = whois.get("registrant_company", "")
                    if registrant_company:
                        output.append(f"    • 注册机构: {registrant_company}")
                    
                    registrant_email = whois.get("registrant_email", "")
                    if registrant_email:
                        output.append(f"    • 注册邮箱: {registrant_email}")
                    
                    cdate = whois.get("cdate", "")
                    if cdate:
                        output.append(f"    • 注册时间: {cdate}")
                    
                    edate = whois.get("edate", "")
                    if edate:
                        output.append(f"    • 过期时间: {edate}")
                    
                    name_server = whois.get("name_server", "")
                    if name_server:
                        # 分割多个域名服务器
                        servers = name_server.split("|")
                        if len(servers) > 1:
                            output.append(f"    • 域名服务器:")
                            for server in servers[:3]:  # 只显示前3个服务器
                                if server.strip():
                                    output.append(f"      - {server.strip()}")
                            if len(servers) > 3:
                                output.append(f"      - ... 还有 {len(servers) - 3} 个服务器")
                        else:
                            output.append(f"    • 域名服务器: {name_server}")
                
                output.append("")
            
            if len(history_whoises) > 5:
                output.append(f"  📈 还有 {len(history_whoises) - 5} 个历史Whois记录")
                output.append("")
        
        # 详细报告链接
        permalink = result.get("permalink", "")
        if permalink:
            output.append(f"📋 详细报告: {permalink}")
        
        # 如果没有任何历史信息
        if not history_ips and not history_whoises:
            output.append("ℹ️ 未找到相关历史信息")
        
        return "\n".join(output) 