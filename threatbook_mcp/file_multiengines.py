"""微步在线威胁分析文件反病毒引擎检测报告模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.file_multiengines")


class FileMultiEnginesTool:
    """文件反病毒引擎检测报告工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="file_multiengines",
            description="文件反病毒引擎检测报告：获取文件经过22款反病毒扫描引擎检测后的结果",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "文件的hash值，支持SHA256/SHA1/MD5"
                    }
                },
                "required": ["hash"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行文件反病毒引擎检测"""
        try:
            hash_value = arguments.get("hash")
            if not hash_value:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'hash'"
                )]
            
            # 调用微步在线威胁分析API
            result = await self.client.get_file_multiengines(hash_value)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"文件反病毒引擎检测失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"检测失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化文件反病毒引擎检测结果"""

        # 使用响应处理器检查状态
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)
        if not is_success:
            return ThreatBookResponseHandler.format_error_message(result)
        
        multiengines = result.get("multiengines", {})
        if not multiengines:
            return "❌ 未找到检测结果"
        
        # 威胁等级
        threat_level = multiengines.get("threat_level", "unknown")
        threat_icons = {
            "malicious": "🚨",
            "suspicious": "⚠️",
            "clean": "✅"
        }
        threat_text = {
            "malicious": "恶意",
            "suspicious": "可疑", 
            "clean": "安全"
        }
        
        icon = threat_icons.get(threat_level, "❓")
        status = threat_text.get(threat_level, "未知")
        
        # 检测统计
        total = multiengines.get("total", 0)
        total2 = multiengines.get("total2", 0)
        positives = multiengines.get("positives", 0)
        scan_date = multiengines.get("scan_date", "")
        
        # 恶意软件信息
        malware_type = multiengines.get("malware_type", "")
        malware_family = multiengines.get("malware_family", "")
        
        output = [
            f"🔍 文件反病毒引擎检测报告",
            f"",
            f"{icon} 威胁等级: {status}",
            f"📊 检出率: {positives}/{total} ({total2}个引擎)",
        ]
        
        if scan_date:
            output.append(f"🕐 扫描时间: {scan_date}")
        
        if malware_type:
            output.append(f"🦠 恶意类型: {malware_type}")
        
        if malware_family:
            output.append(f"👥 恶意家族: {malware_family}")
        
        # 详细检测结果
        scan_results = multiengines.get("scan", {})
        if scan_results:
            output.append("")
            output.append("🔬 详细检测结果:")
            output.append("")
            
            # 分类显示结果
            detected = []
            clean = []
            
            for engine, result_info in scan_results.items():
                if isinstance(result_info, dict):
                    result_text = result_info.get("result", "")
                else:
                    result_text = str(result_info)
                
                if result_text and result_text.lower() != "safe":
                    detected.append(f"  🔴 {engine}: {result_text}")
                else:
                    clean.append(f"  ✅ {engine}: 安全")
            
            # 先显示检出的引擎
            if detected:
                output.append("检出威胁的引擎:")
                output.extend(detected)
                output.append("")
            
            # 显示部分安全的引擎（避免输出过长）
            if clean:
                output.append("安全引擎 (部分显示):")
                output.extend(clean[:5])  # 只显示前5个
                if len(clean) > 5:
                    output.append(f"  ... 还有 {len(clean) - 5} 个引擎显示安全")
        
        return "\n".join(output)
