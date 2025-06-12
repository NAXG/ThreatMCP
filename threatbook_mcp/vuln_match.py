"""微步在线威胁分析产品漏洞匹配模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.vuln_match")


class VulnMatchTool:
    """产品漏洞匹配工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="vuln_match",
            description="产品漏洞匹配：通过厂商产品匹配功能，聚合相关厂商产品的漏洞信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_vendor": {
                        "type": "string",
                        "description": "厂商产品匹配中上传的厂商名称"
                    },
                    "user_product": {
                        "type": "string",
                        "description": "厂商产品匹配中上传的产品名称"
                    },
                    "is_highrisk": {
                        "type": "boolean",
                        "description": "是否只返回高风险漏洞"
                    },
                    "match_time_start": {
                        "type": "string",
                        "description": "匹配开始时间，格式：yyyymmdd（如20240506）"
                    },
                    "match_time_end": {
                        "type": "string",
                        "description": "匹配结束时间，格式：yyyymmdd（如20240506）"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "每页数据量，默认10条，最大50条",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 10
                    },
                    "cursor": {
                        "type": "string",
                        "description": "翻页标识，用于获取下一页数据"
                    }
                },
                "required": []
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行产品漏洞匹配查询"""
        try:
            # 调用微步在线威胁分析API
            result = await self.client.get_vuln_match(arguments)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"产品漏洞匹配查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化产品漏洞匹配结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        total_records = result.get("total_records", 0)
        cursor = result.get("cursor", "")
        items = result.get("items", [])
        
        output = [
            f"🔍 产品漏洞匹配结果",
            f"",
            f"📊 总计: {total_records} 个匹配漏洞",
            f"📄 当前页: {len(items)} 个漏洞",
        ]
        
        if cursor:
            output.append(f"📖 下一页标识: {cursor}")
        
        if not items:
            output.append("")
            output.append("❌ 未找到匹配的漏洞信息")
            return "\n".join(output)
        
        output.append("")
        output.append("=" * 50)
        
        for i, item in enumerate(items, 1):
            output.append("")
            output.append(f"🔸 漏洞 {i}")
            
            # 基本信息
            xve_id = item.get("xve_id", "")
            cve_id = item.get("cve_id", "")
            vuln_name = item.get("vuln_name", "")
            publish_time = item.get("publish_time", "")
            match_time = item.get("match_time", "")
            
            if xve_id:
                output.append(f"  🆔 XVE编号: {xve_id}")
            if cve_id:
                output.append(f"  🆔 CVE编号: {cve_id}")
            if vuln_name:
                output.append(f"  📝 漏洞名称: {vuln_name}")
            if publish_time:
                output.append(f"  📅 发布时间: {publish_time}")
            if match_time:
                output.append(f"  🎯 匹配时间: {match_time}")
            
            # 风险评估
            vpr = item.get("vpr", "")
            risk_level = item.get("risk_level", "")
            if vpr and risk_level:
                risk_icon = "🔴" if risk_level == "高风险" else "🟡" if risk_level == "中风险" else "🟢"
                output.append(f"  {risk_icon} 风险评分: {vpr}/10.0 ({risk_level})")
            
            # 产品匹配信息
            user_vendor = item.get("user_vendor", "")
            user_product = item.get("user_product", "")
            vendor = item.get("vendor", "")
            product = item.get("product", "")
            
            if user_vendor or user_product:
                output.append(f"  🏢 用户产品: {user_vendor} {user_product}")
            if vendor or product:
                output.append(f"  🎯 匹配产品: {vendor} {product}")
            
            # 标签信息
            tags = item.get("tag", [])
            if tags:
                tag_text = ", ".join(tags[:5])  # 只显示前5个标签
                if len(tags) > 5:
                    tag_text += f" 等{len(tags)}个标签"
                output.append(f"  🏷️ 标签: {tag_text}")
            
            # 详情链接
            link = item.get("link", "")
            if link:
                output.append(f"  🔗 详情: {link}")
            
            if i < len(items):  # 不是最后一个
                output.append("")
                output.append("-" * 30)
        
        return "\n".join(output)
