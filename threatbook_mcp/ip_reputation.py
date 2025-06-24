"""微步在线威胁分析IP信誉查询模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.ip_reputation")


class IPReputationTool:
    """IP信誉查询工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="ip_reputation",
            description="查询IP地址的安全信誉信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "要查询的IP地址",
                        "pattern": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    }
                },
                "required": ["ip"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行IP信誉查询"""
        try:
            ip = arguments.get("ip")
            if not ip:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'ip'"
                )]
            
            # 调用微步在线威胁分析API (异步)
            result = await self.client.get_ip_reputation(ip)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"IP信誉查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化IP信誉查询结果"""

        # 使用响应处理器检查状态
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)
        if not is_success:
            return ThreatBookResponseHandler.format_error_message(result)

        # 处理部分成功的情况
        if error_msg:
            # 部分成功，显示警告但继续处理
            pass
        
        data = result.get("data", {})
        
        # 获取第一个IP的数据（通常只有一个IP）
        if not data:
            return "❌ 未找到IP信息"
        
        ip_address = list(data.keys())[0]
        ip_data = data[ip_address]
        
        # 基本信息
        basic = ip_data.get("basic", {})
        location = basic.get("location", {})
        carrier = basic.get("carrier", "未知")
        
        # 地理位置信息
        country = location.get("country", "未知")
        province = location.get("province", "")
        city = location.get("city", "")
        
        location_info = country
        if province:
            location_info += f" {province}"
        if city:
            location_info += f" {city}"
        
        # 安全信息
        is_malicious = ip_data.get("is_malicious", False)
        severity = ip_data.get("severity", "info")
        confidence_level = ip_data.get("confidence_level", "unknown")
        update_time = ip_data.get("update_time", "")
        scene = ip_data.get("scene", "")
        
        # ASN信息
        asn = ip_data.get("asn", {})
        asn_number = asn.get("number", "")
        asn_info = asn.get("info", "")
        
        # 判定结果图标
        if is_malicious:
            severity_icons = {
                "low": "🟡",
                "medium": "🟠", 
                "high": "🔴",
                "critical": "🚨"
            }
            icon = severity_icons.get(severity, "⚠️")
            status_text = "恶意"
        else:
            icon = "✅"
            status_text = "正常"
        
        # 构建格式化输出
        response_code = result.get("response_code", 0)

        output = [
            f"🔍 IP信誉查询结果",
            f"",
        ]

        # 显示部分成功警告
        if error_msg:
            output.append(f"{error_msg}")
            output.append("")

        output.extend([
            f"📍 IP地址: {ip_address}",
            f"🌍 地理位置: {location_info}",
            f"🏢 运营商: {carrier}",
        ])
        
        # ASN信息
        if asn_number and asn_info:
            output.append(f"🌐 ASN: AS{asn_number} ({asn_info})")
        
        output.extend([
            f"",
            f"{icon} 安全状态: {status_text}",
            f"⚡ 威胁等级: {severity}",
            f"🎯 置信度: {confidence_level}",
        ])
        
        # 场景信息
        if scene:
            output.append(f"🏠 场景: {scene}")
        
        # 判定结果
        judgments = ip_data.get("judgments", [])
        if judgments:
            output.append("")
            output.append("🔍 安全判定:")
            for judgment in judgments:
                output.append(f"  • {judgment}")
        
        # 评估信息
        evaluation = ip_data.get("evaluation", {})
        if evaluation:
            output.append("")
            output.append("📊 评估信息:")
            active = evaluation.get("active", "")
            if active:
                output.append(f"  • 活跃度: {active}")
            
            honeypot_hit = evaluation.get("honeypot_hit", False)
            if honeypot_hit:
                output.append(f"  • 蜜罐命中: 是")
        
        # 历史行为
        hist_behavior = ip_data.get("hist_behavior", [])
        if hist_behavior:
            output.append("")
            output.append("📈 历史行为:")
            for behavior in hist_behavior[:5]:  # 只显示前5个
                category = behavior.get("category", "")
                tag_name = behavior.get("tag_name", "")
                tag_desc = behavior.get("tag_desc", "")
                
                if tag_name:
                    output.append(f"  • {category}: {tag_name}")
                    if tag_desc and len(tag_desc) < 100:  # 避免描述过长
                        output.append(f"    {tag_desc}")
        
        # 更新时间
        if update_time:
            output.append("")
            output.append(f"🕐 更新时间: {update_time}")
        
        # 详细报告链接
        permalink = ip_data.get("permalink", "")
        if permalink:
            output.append("")
            output.append(f"📋 详细报告: {permalink}")
        
        return "\n".join(output) 