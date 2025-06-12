"""微步在线威胁分析IP分析模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.ip_analysis")


class IPAnalysisTool:
    """IP分析工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="ip_analysis",
            description="IP分析：全面分析IP地址，包括地理位置、ASN、威胁情报、相关样本、端口信息等",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "要分析的IP地址",
                        "pattern": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    },
                    "exclude": {
                        "type": "string",
                        "description": "可排除的字段，多个用逗号分隔：asn,ports,cas,rdns_list,intelligences,judgments,tags_classes,samples,update_time,sum_cur_domains,scene"
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
        """执行IP分析"""
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
            result = await self.client.get_ip_analysis(ip, exclude, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"IP分析失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"分析失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化IP分析结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        ips = result.get("ips", {})
        if not ips:
            return "❌ 未找到IP信息"
        
        ip_address = list(ips.keys())[0]
        ip_data = ips[ip_address]
        
        output = [
            f"🔍 IP分析结果",
            f"",
            f"📍 IP地址: {ip_address}",
            f""
        ]
        
        # 基本信息
        basic = ip_data.get("basic", {})
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
        
        # ASN信息
        asn = ip_data.get("asn", {})
        if asn:
            asn_number = asn.get("number", "")
            asn_info = asn.get("info", "")
            asn_rank = asn.get("rank", "")
            
            if asn_number and asn_info:
                output.append(f"🌐 ASN: AS{asn_number} ({asn_info})")
                if asn_rank:
                    risk_desc = self._get_risk_description(asn_rank)
                    output.append(f"⚠️ ASN风险等级: {asn_rank}/4 ({risk_desc})")
        
        # 应用场景
        scene = ip_data.get("scene", "")
        if scene:
            output.append(f"🏠 应用场景: {scene}")
        
        output.append("")
        
        # 威胁判定
        judgments = ip_data.get("judgments", [])
        if judgments:
            output.append("🔍 威胁判定:")
            for judgment in judgments:
                output.append(f"  • {judgment}")
            output.append("")
        
        # 标签信息
        tags_classes = ip_data.get("tags_classes", [])
        if tags_classes:
            output.append("🏷️ 相关标签:")
            for tag_class in tags_classes:
                tags_type = tag_class.get("tags_type", "")
                tags = tag_class.get("tags", [])
                if tags:
                    type_desc = self._get_tag_type_description(tags_type)
                    output.append(f"  • {type_desc}: {', '.join(tags)}")
            output.append("")
        
        # 端口信息
        ports = ip_data.get("ports", [])
        if ports:
            output.append("🔌 开放端口:")
            for port_info in ports[:10]:  # 只显示前10个端口
                port = port_info.get("port", "")
                module = port_info.get("module", "")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                
                port_desc = f"  • 端口 {port}"
                if module:
                    port_desc += f" ({module})"
                if product:
                    port_desc += f" - {product}"
                if version:
                    port_desc += f" v{version}"
                
                output.append(port_desc)
            
            if len(ports) > 10:
                output.append(f"  • ... 还有 {len(ports) - 10} 个端口")
            output.append("")
        
        # 相关样本
        samples = ip_data.get("samples", [])
        if samples:
            output.append("🦠 相关样本:")
            for sample in samples[:5]:  # 只显示前5个样本
                sha256 = sample.get("sha256", "")
                malware_type = sample.get("malware_type", "")
                malware_family = sample.get("malware_family", "")
                ratio = sample.get("ratio", "")
                
                sample_desc = f"  • {sha256[:16]}..."
                if malware_family:
                    sample_desc += f" ({malware_family})"
                if malware_type:
                    sample_desc += f" - {malware_type}"
                if ratio:
                    sample_desc += f" 检出率: {ratio}"
                
                output.append(sample_desc)
            
            if len(samples) > 5:
                output.append(f"  • ... 还有 {len(samples) - 5} 个样本")
            output.append("")
        
        # SSL证书信息
        cas = ip_data.get("cas", [])
        if cas:
            output.append("🔒 SSL证书:")
            for ca in cas[:3]:  # 只显示前3个证书
                protocol = ca.get("protocol", "")
                port = ca.get("port", "")
                digital_certificate = ca.get("digital_certificate", {})
                
                if protocol and port:
                    output.append(f"  • {protocol}:{port}")
                
                if digital_certificate:
                    # 提取证书的关键信息
                    subject = digital_certificate.get("subject", "")
                    issuer = digital_certificate.get("issuer", "")
                    if subject:
                        output.append(f"    主题: {subject}")
                    if issuer:
                        output.append(f"    签发者: {issuer}")
            output.append("")
        
        # 当前域名数量
        sum_cur_domains = ip_data.get("sum_cur_domains", "")
        if sum_cur_domains:
            output.append(f"🌐 当前解析域名数量: {sum_cur_domains}")
        
        # 更新时间
        update_time = ip_data.get("update_time", "")
        if update_time:
            output.append(f"🕐 情报更新时间: {update_time}")
        
        # 详细报告链接
        permalink = ip_data.get("permalink", "")
        if permalink:
            output.append("")
            output.append(f"📋 详细报告: {permalink}")
        
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