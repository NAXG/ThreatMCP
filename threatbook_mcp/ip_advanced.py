"""微步在线威胁分析IP高级查询模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.ip_advanced")


class IPAdvancedTool:
    """IP高级查询工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="ip_advanced",
            description="IP高级查询：获取IP的当前域名和历史域名信息，用于深度溯源分析",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "要查询的IP地址",
                        "pattern": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    },
                    "exclude": {
                        "type": "string",
                        "description": "可排除的字段，多个用逗号分隔：asn,cur_domains,history_domains"
                    },
                    "lang": {
                        "type": "string",
                        "description": "返回结果语言，zh为中文，en为英文",
                        "enum": ["zh", "en"],
                        "default": "zh"
                    }
                },
                "required": ["ip"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行IP高级查询"""
        try:
            ip = arguments.get("ip")
            if not ip:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'ip'"
                )]
            
            exclude = arguments.get("exclude", "")
            lang = arguments.get("lang", "zh")
            
            # 调用微步在线威胁分析API
            result = await self.client.get_ip_advanced(ip, exclude, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"IP高级查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化IP高级查询结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        ip = result.get("ip", "")
        if not ip:
            return "❌ 未找到IP信息"
        
        output = [
            f"🔍 IP高级查询结果",
            f"",
            f"📍 IP地址: {ip}",
            f""
        ]
        
        # 基本信息
        basic = result.get("basic", {})
        if basic:
            carrier = basic.get("carrier", "未知")
            location = basic.get("location", {})
            
            if location:
                country = location.get("country", "")
                province = location.get("province", "")
                city = location.get("city", "")
                
                location_info = country
                if province:
                    location_info += f" {province}"
                if city:
                    location_info += f" {city}"
                
                output.append(f"🌍 地理位置: {location_info}")
            
            output.append(f"🏢 运营商: {carrier}")
            output.append("")
        
        # ASN信息
        asn = result.get("asn", {})
        if asn:
            asn_number = asn.get("number", "")
            asn_info = asn.get("info", "")
            asn_rank = asn.get("rank", "")
            
            if asn_number and asn_info:
                output.append(f"🌐 ASN: AS{asn_number} ({asn_info})")
                if asn_rank:
                    risk_desc = self._get_risk_description(asn_rank)
                    output.append(f"⚠️ ASN风险等级: {asn_rank}/4 ({risk_desc})")
                output.append("")
        
        # 当前域名
        cur_domains = result.get("cur_domains", [])
        if cur_domains:
            output.append("🌐 当前指向的域名:")
            domain_count = len(cur_domains)
            
            # 显示前10个域名
            for domain in cur_domains[:10]:
                output.append(f"  • {domain}")
            
            if domain_count > 10:
                output.append(f"  • ... 还有 {domain_count - 10} 个域名")
            
            output.append(f"  📊 总计: {domain_count} 个域名")
            output.append("")
        
        # 历史域名
        history_domains = result.get("history_domains", {})
        if history_domains:
            output.append("📅 历史域名记录:")
            
            # 按日期排序显示历史域名
            sorted_dates = sorted(history_domains.keys(), reverse=True)
            
            for i, date in enumerate(sorted_dates[:5]):  # 只显示最近5个日期
                domains = history_domains[date]
                output.append(f"  📅 {date}:")
                
                if isinstance(domains, list):
                    domain_count = len(domains)
                    # 显示前5个域名
                    for domain in domains[:5]:
                        output.append(f"    • {domain}")
                    
                    if domain_count > 5:
                        output.append(f"    • ... 还有 {domain_count - 5} 个域名")
                    
                    output.append(f"    📊 当日域名数: {domain_count}")
                else:
                    output.append(f"    • {domains}")
                
                output.append("")
            
            if len(sorted_dates) > 5:
                output.append(f"  📈 还有 {len(sorted_dates) - 5} 个历史日期的记录")
                output.append("")
        
        # 详细报告链接
        permalink = result.get("permalink", "")
        if permalink:
            output.append(f"📋 详细报告: {permalink}")
        
        # 如果没有任何域名信息
        if not cur_domains and not history_domains:
            output.append("ℹ️ 未找到相关域名信息")
        
        return "\n".join(output)
    
    def _get_risk_description(self, rank: int) -> str:
        """获取风险等级描述"""
        descriptions = {
            0: "无风险",
            1: "低风险",
            2: "中风险", 
            3: "高风险",
            4: "极高风险"
        }
        return descriptions.get(rank, "未知") 