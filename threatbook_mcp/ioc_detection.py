"""微步在线威胁分析失陷检测模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.ioc_detection")


class IOCDetectionTool:
    """失陷检测工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="ioc_detection",
            description="失陷检测：检测IP地址或域名的恶意威胁，识别远控(C2)、恶意软件、矿池等威胁",
            inputSchema={
                "type": "object",
                "properties": {
                    "resource": {
                        "type": "string",
                        "description": "要检测的IP地址或域名。支持批量查询，多个用逗号分隔，最多100个。IP可带端口，格式如：8.8.8.8:80"
                    },
                    "lang": {
                        "type": "string",
                        "description": "返回结果语言，zh为中文，en为英文",
                        "enum": ["zh", "en"],
                        "default": "zh"
                    }
                },
                "required": ["resource"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行失陷检测"""
        try:
            resource = arguments.get("resource")
            if not resource:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'resource'"
                )]
            
            lang = arguments.get("lang", "zh")
            
            # 调用微步在线威胁分析API
            result = await self.client.get_ioc_detection(resource, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"失陷检测失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"检测失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化失陷检测结果"""

        # 使用响应处理器检查状态
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)
        if not is_success:
            return ThreatBookResponseHandler.format_error_message(result)

        # 处理部分成功的情况
        warning_msg = error_msg if error_msg else ""

        output = ["🔍 失陷检测结果", ""]

        # 显示部分成功警告
        if warning_msg:
            output.append(f"{warning_msg}")
            output.append("")
        
        # 处理IP检测结果
        ips = result.get("ips", {})
        if ips:
            output.append("📍 IP检测结果:")
            output.append("")
            
            for ip, ip_data in ips.items():
                ip_result = self._format_ip_result(ip, ip_data)
                output.extend(ip_result)
                output.append("")
        
        # 处理域名检测结果
        domains = result.get("domains", {})
        if domains:
            output.append("🌐 域名检测结果:")
            output.append("")
            
            for domain, domain_data in domains.items():
                domain_result = self._format_domain_result(domain, domain_data)
                output.extend(domain_result)
                output.append("")
        
        # 处理排名信息
        rank = result.get("rank", {})
        if rank and domains:
            rank_result = self._format_rank_result(rank)
            if rank_result:
                output.extend(rank_result)
        
        # 如果没有任何结果
        if not ips and not domains:
            output.append("ℹ️ 未检测到任何威胁信息")
        
        return "\n".join(output)
    
    def _format_ip_result(self, ip: str, data: Dict[str, Any]) -> List[str]:
        """格式化单个IP的检测结果"""
        
        is_malicious = data.get("is_malicious", False)
        confidence_level = data.get("confidence_level", "unknown")
        severity = data.get("severity", "info")
        judgments = data.get("judgments", [])
        tags_classes = data.get("tags_classes", [])
        permalink = data.get("permalink", "")
        
        # 威胁等级图标
        if is_malicious:
            severity_icons = {
                "critical": "🚨",
                "high": "🔴",
                "medium": "🟠",
                "low": "🟡"
            }
            icon = severity_icons.get(severity, "⚠️")
            status_text = "恶意"
        else:
            icon = "✅"
            status_text = "正常"
        
        result = [
            f"  📍 {ip}",
            f"  {icon} 状态: {status_text}",
            f"  ⚡ 威胁等级: {severity}",
            f"  🎯 置信度: {confidence_level}",
        ]
        
        # 威胁类型判定
        if judgments:
            result.append("  🔍 威胁类型:")
            for judgment in judgments:
                # 添加威胁类型的中文说明
                threat_desc = self._get_threat_description(judgment)
                if threat_desc:
                    result.append(f"    • {judgment} ({threat_desc})")
                else:
                    result.append(f"    • {judgment}")
        
        # 攻击团伙或安全事件信息
        if tags_classes:
            result.append("  🏷️ 相关标签:")
            for tag_class in tags_classes:
                tags_type = tag_class.get("tags_type", "")
                tags = tag_class.get("tags", [])
                if tags:
                    type_desc = self._get_tag_type_description(tags_type)
                    result.append(f"    • {type_desc}: {', '.join(tags)}")
        
        # 详细报告链接
        if permalink:
            result.append(f"  📋 详细报告: {permalink}")
        
        return result
    
    def _format_domain_result(self, domain: str, data: Dict[str, Any]) -> List[str]:
        """格式化单个域名的检测结果"""
        
        is_malicious = data.get("is_malicious", False)
        confidence_level = data.get("confidence_level", "unknown")
        severity = data.get("severity", "info")
        judgments = data.get("judgments", [])
        tags_classes = data.get("tags_classes", [])
        categories = data.get("categories", {})
        permalink = data.get("permalink", "")
        
        # 威胁等级图标
        if is_malicious:
            severity_icons = {
                "critical": "🚨",
                "high": "🔴",
                "medium": "🟠",
                "low": "🟡"
            }
            icon = severity_icons.get(severity, "⚠️")
            status_text = "恶意"
        else:
            icon = "✅"
            status_text = "正常"
        
        result = [
            f"  🌐 {domain}",
            f"  {icon} 状态: {status_text}",
            f"  ⚡ 威胁等级: {severity}",
            f"  🎯 置信度: {confidence_level}",
        ]
        
        # 域名分类
        if categories:
            first_cats = categories.get("first_cats", [])
            second_cats = categories.get("second_cats", "")
            
            if first_cats or second_cats:
                result.append("  📂 域名分类:")
                if first_cats:
                    result.append(f"    • 一级分类: {', '.join(first_cats)}")
                if second_cats:
                    result.append(f"    • 二级分类: {second_cats}")
        
        # 威胁类型判定
        if judgments:
            result.append("  🔍 威胁类型:")
            for judgment in judgments:
                threat_desc = self._get_threat_description(judgment)
                if threat_desc:
                    result.append(f"    • {judgment} ({threat_desc})")
                else:
                    result.append(f"    • {judgment}")
        
        # 攻击团伙或安全事件信息
        if tags_classes:
            result.append("  🏷️ 相关标签:")
            for tag_class in tags_classes:
                tags_type = tag_class.get("tags_type", "")
                tags = tag_class.get("tags", [])
                if tags:
                    type_desc = self._get_tag_type_description(tags_type)
                    result.append(f"    • {type_desc}: {', '.join(tags)}")
        
        # 详细报告链接
        if permalink:
            result.append(f"  📋 详细报告: {permalink}")
        
        return result
    
    def _format_rank_result(self, rank: Dict[str, Any]) -> List[str]:
        """格式化排名信息"""
        
        result = ["📊 排名信息:"]
        
        # Alexa排名
        alexa_rank = rank.get("alexa_rank", {})
        if alexa_rank:
            for domain, rank_data in alexa_rank.items():
                global_rank = rank_data.get("global_rank", -1)
                if global_rank > 0:
                    result.append(f"  • {domain} Alexa全球排名: {global_rank:,}")
        
        # Umbrella排名
        umbrella_rank = rank.get("umbrella_rank", {})
        if umbrella_rank:
            for domain, rank_data in umbrella_rank.items():
                global_rank = rank_data.get("global_rank", -1)
                if global_rank > 0:
                    result.append(f"  • {domain} Umbrella排名: {global_rank:,}")
        
        return result if len(result) > 1 else []
    
    def _get_threat_description(self, threat_type: str) -> str:
        """获取威胁类型的中文描述"""
        descriptions = {
            "C2": "远程控制",
            "Sinkhole C2": "安全机构接管的C2",
            "MiningPool": "矿池",
            "CoinMiner": "私有矿池",
            "Malware": "恶意软件",
            "Whitelist": "白名单",
            "Info": "基础信息"
        }
        return descriptions.get(threat_type, "")
    
    def _get_tag_type_description(self, tag_type: str) -> str:
        """获取标签类型的中文描述"""
        descriptions = {
            "industry": "行业",
            "gangs": "团伙",
            "virus_family": "病毒家族",
            "malware_family": "恶意软件家族",
            "apt": "APT组织"
        }
        return descriptions.get(tag_type, tag_type) 