"""微步在线威胁分析文件上传分析模块"""

import logging
from typing import Any, Dict, List
import mcp.types as types
from threatbook_mcp.response_handler import ThreatBookResponseHandler

logger = logging.getLogger("threatbook-mcp.file_upload")


class FileUploadTool:
    """文件上传分析工具"""
    
    def __init__(self, client):
        self.client = client
    
    def get_tool_definition(self) -> types.Tool:
        """获取工具定义"""
        return types.Tool(
            name="file_upload",
            description="提交文件分析：上传文件进行沙箱分析，支持PE、Office、PDF、Script等文件类型",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "要上传分析的文件路径"
                    },
                    "sandbox_type": {
                        "type": "string",
                        "description": "指定沙箱环境，如：win7_sp1_enx64_office2013, ubuntu_1704_x64, kylin_desktop_v10等"
                    },
                    "run_time": {
                        "type": "integer",
                        "description": "沙箱运行时间（秒），默认60秒，最大300秒",
                        "minimum": 1,
                        "maximum": 300,
                        "default": 60
                    }
                },
                "required": ["file_path"]
            }
        )
    
    async def execute(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """执行文件上传分析"""
        try:
            file_path = arguments.get("file_path")
            if not file_path:
                return [types.TextContent(
                    type="text",
                    text="错误：缺少必需的参数 'file_path'"
                )]
            
            sandbox_type = arguments.get("sandbox_type")
            run_time = arguments.get("run_time", 60)
            
            # 调用微步在线威胁分析API
            result = await self.client.upload_file_analysis(file_path, sandbox_type, run_time)
            
            # 格式化结果
            formatted_result = self.format_result(result)
            
            return [types.TextContent(
                type="text",
                text=formatted_result
            )]
            
        except Exception as e:
            logger.error(f"文件上传分析失败: {e}")
            return [types.TextContent(
                type="text",
                text=f"上传失败: {str(e)}"
            )]
    
    def format_result(self, result: Dict[str, Any]) -> str:
        """格式化文件上传分析结果"""
        
        # 使用响应处理器检查状态

        
        is_success, error_msg = ThreatBookResponseHandler.check_response(result)

        
        if not is_success:

        
            return ThreatBookResponseHandler.format_error_message(result)

        
        

        
        # 处理部分成功的情况

        
        if error_msg:

        
            # 部分成功，显示警告但继续处理

        
            pass
        
        sha256 = result.get("sha256", "")
        permalink = result.get("permalink", "")
        
        output = [
            f"📤 文件上传分析",
            f"",
            f"✅ 文件上传成功",
            f"🔑 文件SHA256: {sha256}",
        ]
        
        if permalink:
            output.append(f"🔗 分析报告: {permalink}")
        
        output.extend([
            f"",
            f"⏳ 文件正在沙箱中分析，请稍后使用file_analysis工具查询详细报告",
            f"💡 提示：可以使用SHA256值查询分析结果"
        ])
        
        return "\n".join(output)
