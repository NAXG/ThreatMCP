"""微步在线威胁分析文件信誉报告模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.file_analysis")


class FileAnalysisTool:
    """文件信誉报告工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="file_analysis",
            description="文件信誉报告：获取文件详细的静态和动态分析报告，包括威胁等级、行为签名、网络行为等",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "文件的hash值，支持SHA256/SHA1/MD5"
                    },
                    "sandbox_type": {
                        "type": "string",
                        "description": "指定沙箱环境，如：win7_sp1_enx64_office2013, ubuntu_1704_x64等"
                    },
                    "query_fields": {
                        "type": "string",
                        "description": "查询字段，多个用逗号分隔：summary,network,signature,static,dropped,pstree,multiengines,strings"
                    }
                },
                "required": ["hash"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行文件信誉报告查询"""
        try:
            hash_value = arguments.get("hash")
            if not hash_value:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'hash'"
                )]
            
            sandbox_type = arguments.get("sandbox_type", "")
            query_fields = arguments.get("query_fields", "")
            
            # 调用微步在线威胁分析API
            result = await self.client.get_file_analysis(hash_value, sandbox_type, query_fields)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"文件信誉报告查询失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"查询失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化文件信誉报告结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        output = [
            f"🔍 文件信誉报告",
            f""
        ]
        
        # 概要信息
        summary = result.get("summary", {})
        if summary:
            output.extend(self._format_summary(summary))
        
        # 多引擎扫描结果
        multiengines = result.get("multiengines", {})
        if multiengines:
            output.extend(self._format_multiengines(multiengines))
        
        # 行为签名
        signature = result.get("signature", [])
        if signature:
            output.extend(self._format_signature(signature))
        
        # 网络行为
        network = result.get("network", {})
        if network:
            output.extend(self._format_network(network))
        
        # 释放文件
        dropped = result.get("dropped", [])
        if dropped:
            output.extend(self._format_dropped(dropped))
        
        # 详细报告链接
        permalink = result.get("permalink", "")
        if permalink:
            output.append("")
            output.append(f"📋 详细报告: {permalink}")
        
        return "\n".join(output)
    
    def _format_summary(self, summary: Dict[str, Any]) -> List[str]:
        """格式化概要信息"""
        output = ["📊 文件概要:"]
        
        # 基本信息
        file_name = summary.get("file_name", "")
        if file_name:
            output.append(f"  📄 文件名: {file_name}")
        
        file_type = summary.get("file_type", "")
        if file_type:
            output.append(f"  📋 文件类型: {file_type}")
        
        sample_sha256 = summary.get("sample_sha256", "")
        if sample_sha256:
            output.append(f"  🔑 SHA256: {sample_sha256}")
        
        md5 = summary.get("md5", "")
        if md5:
            output.append(f"  🔑 MD5: {md5}")
        
        # 威胁信息
        threat_level = summary.get("threat_level", "")
        if threat_level:
            threat_icons = {
                "malicious": "🔴",
                "suspicious": "🟡",
                "clean": "✅"
            }
            icon = threat_icons.get(threat_level, "⚠️")
            output.append(f"  {icon} 威胁等级: {threat_level}")
        
        malware_type = summary.get("malware_type", "")
        if malware_type:
            output.append(f"  🦠 恶意类型: {malware_type}")
        
        malware_family = summary.get("malware_family", "")
        if malware_family:
            output.append(f"  👥 恶意家族: {malware_family}")
        
        is_whitelist = summary.get("is_whitelist", False)
        if is_whitelist:
            output.append(f"  ✅ 白名单文件: 是")
        
        # 时间信息
        submit_time = summary.get("submit_time", "")
        if submit_time:
            output.append(f"  📅 提交时间: {submit_time}")
        
        # 检测信息
        multi_engines = summary.get("multi_engines", "")
        if multi_engines:
            output.append(f"  🔍 检出率: {multi_engines}")
        
        threat_score = summary.get("threat_score", "")
        if threat_score:
            output.append(f"  📊 威胁评分: {threat_score}")
        
        output.append("")
        return output
    
    def _format_multiengines(self, multiengines: Dict[str, Any]) -> List[str]:
        """格式化多引擎扫描结果"""
        output = ["🔍 多引擎扫描结果:"]
        
        threat_level = multiengines.get("threat_level", "")
        if threat_level:
            threat_icons = {
                "malicious": "🔴",
                "suspicious": "🟡", 
                "clean": "✅"
            }
            icon = threat_icons.get(threat_level, "⚠️")
            output.append(f"  {icon} 综合判定: {threat_level}")
        
        total = multiengines.get("total", 0)
        positives = multiengines.get("positives", 0)
        if total > 0:
            output.append(f"  📊 检出情况: {positives}/{total}")
        
        scan_date = multiengines.get("scan_date", "")
        if scan_date:
            output.append(f"  📅 扫描时间: {scan_date}")
        
        # 具体引擎结果
        scan = multiengines.get("scan", {})
        if scan:
            detected_engines = []
            safe_engines = []
            
            for engine, result_info in scan.items():
                if isinstance(result_info, dict):
                    result_value = result_info.get("result", "")
                else:
                    result_value = str(result_info)
                
                if result_value and result_value.lower() != "safe":
                    detected_engines.append(f"{engine}: {result_value}")
                else:
                    safe_engines.append(engine)
            
            if detected_engines:
                output.append(f"  ⚠️ 检出引擎 ({len(detected_engines)}):")
                for detection in detected_engines[:5]:  # 只显示前5个
                    output.append(f"    • {detection}")
                if len(detected_engines) > 5:
                    output.append(f"    • ... 还有 {len(detected_engines) - 5} 个引擎检出")
        
        output.append("")
        return output
    
    def _format_signature(self, signature: List[Dict[str, Any]]) -> List[str]:
        """格式化行为签名"""
        if not signature:
            return []
        
        output = ["🎯 行为签名:"]
        
        # 按严重级别排序
        sorted_signatures = sorted(signature, key=lambda x: x.get("severity", 0), reverse=True)
        
        for sig in sorted_signatures[:10]:  # 只显示前10个
            name = sig.get("name", "")
            severity = sig.get("severity", 0)
            description = sig.get("description", "")
            sig_class = sig.get("sig_class", "")
            
            # 严重级别图标
            if severity >= 8:
                icon = "🚨"
            elif severity >= 6:
                icon = "🔴"
            elif severity >= 4:
                icon = "🟠"
            elif severity >= 2:
                icon = "🟡"
            else:
                icon = "ℹ️"
            
            output.append(f"  {icon} {name} (严重级别: {severity})")
            if sig_class:
                output.append(f"    分类: {sig_class}")
            if description and len(description) < 100:
                output.append(f"    描述: {description}")
        
        if len(signature) > 10:
            output.append(f"  📊 还有 {len(signature) - 10} 个行为签名")
        
        output.append("")
        return output
    
    def _format_network(self, network: Dict[str, Any]) -> List[str]:
        """格式化网络行为"""
        output = ["🌐 网络行为:"]
        
        # DNS查询
        dns = network.get("dns", [])
        if dns:
            output.append(f"  🔍 DNS查询 ({len(dns)}):")
            for query in dns[:5]:
                if isinstance(query, dict):
                    domain = query.get("hostname", query.get("domain", ""))
                    if domain:
                        output.append(f"    • {domain}")
                else:
                    output.append(f"    • {query}")
            if len(dns) > 5:
                output.append(f"    • ... 还有 {len(dns) - 5} 个查询")
        
        # HTTP请求
        http = network.get("http", [])
        if http:
            output.append(f"  🌐 HTTP请求 ({len(http)}):")
            for request in http[:5]:
                if isinstance(request, dict):
                    url = request.get("url", request.get("uri", ""))
                    method = request.get("method", "")
                    if url:
                        display_url = url if len(url) < 80 else url[:80] + "..."
                        output.append(f"    • {method} {display_url}" if method else f"    • {display_url}")
                else:
                    output.append(f"    • {request}")
            if len(http) > 5:
                output.append(f"    • ... 还有 {len(http) - 5} 个请求")
        
        # 连接的主机
        hosts = network.get("hosts", [])
        if hosts:
            output.append(f"  🖥️ 连接主机 ({len(hosts)}):")
            for host in hosts[:5]:
                if isinstance(host, dict):
                    ip = host.get("ip", host.get("host", ""))
                    port = host.get("port", "")
                    if ip:
                        display_host = f"{ip}:{port}" if port else ip
                        output.append(f"    • {display_host}")
                else:
                    output.append(f"    • {host}")
            if len(hosts) > 5:
                output.append(f"    • ... 还有 {len(hosts) - 5} 个主机")
        
        output.append("")
        return output
    
    def _format_dropped(self, dropped: List[Dict[str, Any]]) -> List[str]:
        """格式化释放文件"""
        if not dropped:
            return []
        
        output = [f"📁 释放文件 ({len(dropped)}):"]
        
        for file_info in dropped[:10]:  # 只显示前10个
            name = file_info.get("name", "")
            filepath = file_info.get("filepath", "")
            size = file_info.get("size", "")
            file_type = file_info.get("type", "")
            sha256 = file_info.get("sha256", "")
            
            if name:
                output.append(f"  📄 {name}")
            elif filepath:
                output.append(f"  📄 {filepath}")
            
            if size:
                size_kb = int(size) // 1024 if str(size).isdigit() else size
                output.append(f"    大小: {size_kb}KB" if str(size_kb).isdigit() else f"    大小: {size}")
            
            if file_type:
                output.append(f"    类型: {file_type}")
            
            if sha256:
                output.append(f"    SHA256: {sha256[:32]}...")
            
            output.append("")
        
        if len(dropped) > 10:
            output.append(f"  📊 还有 {len(dropped) - 10} 个释放文件")
        
        output.append("")
        return output 