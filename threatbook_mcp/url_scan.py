"""微步在线威胁分析URL扫描模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.url_scan")


class URLScanTool:
    """URL扫描工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="url_scan",
            description="提交URL分析：通过11款URL扫描引擎和黑名单服务对URL进行检测，同时分析下载的文件",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "要扫描的URL地址"
                    }
                },
                "required": ["url"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行URL扫描"""
        try:
            url = arguments.get("url")
            if not url:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'url'"
                )]
            
            # 调用微步在线威胁分析API
            result = await self.client.scan_url(url)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"URL扫描失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"扫描失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化URL扫描结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        url = result.get("url", "")
        scan_time = result.get("time", "")
        permalink = result.get("permalink", "")
        
        output = [
            f"🔍 URL扫描分析",
            f"",
            f"🌐 URL: {url}",
            f"✅ 扫描提交成功",
        ]
        
        if scan_time:
            output.append(f"🕐 扫描时间: {scan_time}")
        
        if permalink:
            output.append(f"🔗 详细报告: {permalink}")
        
        output.extend([
            f"",
            f"⏳ URL正在扫描分析中，请稍后使用url_report工具查询详细结果",
            f"💡 提示：可以使用相同的URL查询扫描结果"
        ])
        
        return "\n".join(output)
