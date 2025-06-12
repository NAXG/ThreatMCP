"""微步在线威胁分析域名分析模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.domain_analysis")


class DomainAnalysisTool:
    """域名分析工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="domain_analysis",
            description="域名分析：全面分析域名，包括解析IP、Whois、威胁情报、相关样本、域名分类等",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "要分析的域名"
                    },
                    "exclude": {
                        "type": "string",
                        "description": "可排除的字段，多个用逗号分隔：cur_ips,cur_whois,cas,intelligences,judgments,tags_classes,samples,categories,sum_sub_domains,sum_cur_ips"
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
        """执行域名分析"""
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
            result = await self.client.get_domain_analysis(domain, exclude, lang)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"域名分析失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"分析失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化域名分析结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        domains = result.get("domains", {})
        if not domains:
            return "❌ 未找到域名信息"
        
        domain = list(domains.keys())[0]
        domain_data = domains[domain]
        
        output = [
            f"🔍 域名分析结果",
            f"",
            f"🌐 域名: {domain}",
            f""
        ]
        
        # 域名分类
        categories = domain_data.get("categories", {})
        if categories:
            first_cats = categories.get("first_cats", [])
            second_cats = categories.get("second_cats", "")
            
            if first_cats or second_cats:
                output.append("📂 域名分类:")
                if first_cats:
                    output.append(f"  • 一级分类: {', '.join(first_cats)}")
                if second_cats:
                    output.append(f"  • 二级分类: {second_cats}")
                output.append("")
        
        # 当前解析IP
        cur_ips = domain_data.get("cur_ips", [])
        if cur_ips:
            output.append("📍 当前解析IP:")
            for ip_info in cur_ips[:5]:  # 只显示前5个IP
                ip = ip_info.get("ip", "")
                carrier = ip_info.get("carrier", "")
                location = ip_info.get("location", {})
                
                ip_desc = f"  • {ip}"
                
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
            
            if len(cur_ips) > 5:
                output.append(f"  • ... 还有 {len(cur_ips) - 5} 个IP")
            output.append("")
        
        # 威胁判定
        judgments = domain_data.get("judgments", [])
        if judgments:
            output.append("🔍 威胁判定:")
            for judgment in judgments:
                output.append(f"  • {judgment}")
            output.append("")
        
        # 标签信息
        tags_classes = domain_data.get("tags_classes", [])
        if tags_classes:
            output.append("🏷️ 相关标签:")
            for tag_class in tags_classes:
                tags_type = tag_class.get("tags_type", "")
                tags = tag_class.get("tags", [])
                if tags:
                    type_desc = self._get_tag_type_description(tags_type)
                    output.append(f"  • {type_desc}: {', '.join(tags)}")
            output.append("")
        
        # 排名信息
        rank = domain_data.get("rank", {})
        if rank:
            output.append("📊 排名信息:")
            alexa_rank = rank.get("alexa_rank", {})
            umbrella_rank = rank.get("umbrella_rank", {})
            
            if alexa_rank:
                global_rank = alexa_rank.get("global_rank", -1)
                if global_rank > 0:
                    output.append(f"  • Alexa全球排名: {global_rank:,}")
            
            if umbrella_rank:
                global_rank = umbrella_rank.get("global_rank", -1)
                if global_rank > 0:
                    output.append(f"  • Umbrella排名: {global_rank:,}")
            
            if alexa_rank or umbrella_rank:
                output.append("")
        
        # Whois信息
        cur_whois = domain_data.get("cur_whois", {})
        if cur_whois:
            output.append("📋 Whois信息:")
            
            registrar_name = cur_whois.get("registrar_name", "")
            if registrar_name:
                output.append(f"  • 注册商: {registrar_name}")
            
            registrant_name = cur_whois.get("registrant_name", "")
            if registrant_name:
                output.append(f"  • 注册者: {registrant_name}")
            
            registrant_company = cur_whois.get("registrant_company", "")
            if registrant_company:
                output.append(f"  • 注册机构: {registrant_company}")
            
            cdate = cur_whois.get("cdate", "")
            if cdate:
                output.append(f"  • 注册时间: {cdate}")
            
            edate = cur_whois.get("edate", "")
            if edate:
                output.append(f"  • 过期时间: {edate}")
            
            output.append("")
        
        # ICP备案信息
        icp = domain_data.get("icp", {})
        if icp:
            output.append("🏛️ ICP备案:")
            
            owner = icp.get("owner", "")
            if owner:
                output.append(f"  • 域名归属: {owner}")
            
            company_name = icp.get("company_name", "")
            if company_name:
                output.append(f"  • 备案单位: {company_name}")
            
            site_license = icp.get("site_license", "")
            if site_license:
                output.append(f"  • 备案编号: {site_license}")
            
            site_name = icp.get("site_name", "")
            if site_name:
                output.append(f"  • 网站名称: {site_name}")
            
            output.append("")
        
        # 相关样本
        samples = domain_data.get("samples", [])
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
        
        # 统计信息
        sum_sub_domains = domain_data.get("sum_sub_domains", "")
        sum_cur_ips = domain_data.get("sum_cur_ips", "")
        
        if sum_sub_domains or sum_cur_ips:
            output.append("📈 统计信息:")
            if sum_sub_domains:
                output.append(f"  • 子域名数量: {sum_sub_domains}")
            if sum_cur_ips:
                output.append(f"  • 当前解析IP数量: {sum_cur_ips}")
            output.append("")
        
        # 详细报告链接
        permalink = domain_data.get("permalink", "")
        if permalink:
            output.append(f"📋 详细报告: {permalink}")
        
        return "\n".join(output)
    
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