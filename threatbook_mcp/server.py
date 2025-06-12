#!/usr/bin/env python3
"""微步在线威胁分析MCP服务器"""

import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

import httpx
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types
from pydantic import BaseModel, Field

# 导入工具模块
from threatbook_mcp.ip_reputation import IPReputationTool
from threatbook_mcp.ioc_detection import IOCDetectionTool
from threatbook_mcp.domain_context import DomainContextTool
from threatbook_mcp.ip_analysis import IPAnalysisTool
from threatbook_mcp.domain_analysis import DomainAnalysisTool
from threatbook_mcp.ip_advanced import IPAdvancedTool
from threatbook_mcp.domain_advanced import DomainAdvancedTool
from threatbook_mcp.subdomain import SubdomainTool
from threatbook_mcp.file_analysis import FileAnalysisTool
from threatbook_mcp.file_multiengines import FileMultiEnginesTool
from threatbook_mcp.file_upload import FileUploadTool
from threatbook_mcp.url_scan import URLScanTool
from threatbook_mcp.url_report import URLReportTool
from threatbook_mcp.vulnerability import VulnerabilityTool
from threatbook_mcp.vuln_match import VulnMatchTool
from threatbook_mcp.response_handler import ThreatBookResponseHandler

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatbook-mcp")

# 微步在线威胁分析API配置
THREATBOOK_API_BASE = "https://api.threatbook.cn/v3"
DEFAULT_TIMEOUT = 30


class ThreatBookConfig(BaseModel):
    """微步在线威胁分析配置"""
    api_key: str = Field(..., description="微步在线威胁分析API密钥")
    base_url: str = Field(default=THREATBOOK_API_BASE, description="API基础URL")
    timeout: int = Field(default=DEFAULT_TIMEOUT, description="请求超时时间（秒）")


class ThreatBookClient:
    """微步在线威胁分析API异步客户端"""

    def __init__(self, config: ThreatBookConfig):
        self.config = config
        # 使用单个 AsyncClient 复用连接，HTTP/2 可提升性能
        self.session = httpx.AsyncClient(timeout=config.timeout)

    async def aclose(self):
        """关闭底层 HTTP 连接"""
        await self.session.aclose()

    async def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """查询IP信誉"""
        url = f"{self.config.base_url}/scene/ip_reputation"
        params = {
            "apikey": self.config.api_key,
            "resource": ip
        }
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_ioc_detection(self, resource: str, lang: str = "zh") -> Dict[str, Any]:
        """失陷检测"""
        url = f"{self.config.base_url}/scene/ioc"
        params = {
            "apikey": self.config.api_key,
            "resource": resource,
            "lang": lang
        }
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_domain_context(self, domain: str, lang: str = "zh") -> Dict[str, Any]:
        """域名上下文查询"""
        url = f"{self.config.base_url}/scene/domain_context"
        params = {
            "apikey": self.config.api_key,
            "resource": domain,
            "lang": lang
        }
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_ip_analysis(self, ip: str, exclude: str = "", lang: str = "zh") -> Dict[str, Any]:
        """IP分析"""
        url = f"{self.config.base_url}/ip/query"
        params = {
            "apikey": self.config.api_key,
            "resource": ip,
            "lang": lang
        }
        if exclude:
            params["exclude"] = exclude
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_domain_analysis(self, domain: str, exclude: str = "", lang: str = "zh") -> Dict[str, Any]:
        """域名分析"""
        url = f"{self.config.base_url}/domain/query"
        params = {
            "apikey": self.config.api_key,
            "resource": domain,
            "lang": lang
        }
        if exclude:
            params["exclude"] = exclude
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_ip_advanced(self, ip: str, exclude: str = "", lang: str = "zh") -> Dict[str, Any]:
        """IP高级查询"""
        url = f"{self.config.base_url}/ip/adv_query"
        params = {
            "apikey": self.config.api_key,
            "resource": ip,
            "lang": lang
        }
        if exclude:
            params["exclude"] = exclude
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_domain_advanced(self, domain: str, exclude: str = "", lang: str = "zh") -> Dict[str, Any]:
        """域名高级查询"""
        url = f"{self.config.base_url}/domain/adv_query"
        params = {
            "apikey": self.config.api_key,
            "resource": domain,
            "lang": lang
        }
        if exclude:
            params["exclude"] = exclude
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_subdomain(self, domain: str, lang: str = "zh") -> Dict[str, Any]:
        """子域名查询"""
        url = f"{self.config.base_url}/domain/sub_domains"
        params = {
            "apikey": self.config.api_key,
            "resource": domain,
            "lang": lang
        }
        
        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")
    
    async def get_file_analysis(self, hash_value: str, sandbox_type: str = "", query_fields: str = "") -> Dict[str, Any]:
        """文件信誉报告"""
        url = f"{self.config.base_url}/file/report"
        params = {
            "apikey": self.config.api_key,
            "resource": hash_value
        }
        if sandbox_type:
            params["sandbox_type"] = sandbox_type
        if query_fields:
            params["query_fields"] = query_fields

        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")

    async def get_file_multiengines(self, hash_value: str) -> Dict[str, Any]:
        """文件反病毒引擎检测报告"""
        url = f"{self.config.base_url}/file/report/multiengines"
        params = {
            "apikey": self.config.api_key,
            "resource": hash_value
        }

        try:
            response = await self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")

    async def upload_file_analysis(self, file_path: str, sandbox_type: str = "", run_time: int = 60) -> Dict[str, Any]:
        """提交文件分析"""
        url = f"{self.config.base_url}/file/upload"
        data = {
            "apikey": self.config.api_key
        }
        if sandbox_type:
            data["sandbox_type"] = sandbox_type
        if run_time:
            data["run_time"] = run_time

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = await self.session.post(url, data=data, files=files)
            response.raise_for_status()
            return response.json()
        except FileNotFoundError:
            raise Exception(f"文件不存在: {file_path}")
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """提交URL分析"""
        api_url = f"{self.config.base_url}/url/scan"
        params = {
            "apikey": self.config.api_key,
            "url": url
        }

        try:
            response = await self.session.get(api_url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")

    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """URL信誉报告"""
        api_url = f"{self.config.base_url}/url/report"
        params = {
            "apikey": self.config.api_key,
            "url": url
        }

        try:
            response = await self.session.get(api_url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")

    async def get_vulnerability_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """漏洞情报"""
        api_url = f"{self.config.base_url}/vuln"
        api_params = {
            "apikey": self.config.api_key
        }
        api_params.update(params)

        try:
            response = await self.session.get(api_url, params=api_params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")

    async def get_vuln_match(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """产品漏洞匹配"""
        api_url = f"{self.config.base_url}/vuln/match"
        api_params = {
            "apikey": self.config.api_key
        }
        api_params.update(params)

        try:
            response = await self.session.get(api_url, params=api_params)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"请求微步在线威胁分析API失败: {e}")
            raise Exception(f"API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析API响应失败: {e}")
            raise Exception(f"响应解析失败: {str(e)}")


# 创建服务器实例
server = Server("threatbook-mcp")

# 全局客户端实例和工具实例
threatbook_client: Optional[ThreatBookClient] = None
ip_reputation_tool: Optional[IPReputationTool] = None
ioc_detection_tool: Optional[IOCDetectionTool] = None
domain_context_tool: Optional[DomainContextTool] = None
ip_analysis_tool: Optional[IPAnalysisTool] = None
domain_analysis_tool: Optional[DomainAnalysisTool] = None
ip_advanced_tool: Optional[IPAdvancedTool] = None
domain_advanced_tool: Optional[DomainAdvancedTool] = None
subdomain_tool: Optional[SubdomainTool] = None
file_analysis_tool: Optional[FileAnalysisTool] = None
file_multiengines_tool: Optional[FileMultiEnginesTool] = None
file_upload_tool: Optional[FileUploadTool] = None
url_scan_tool: Optional[URLScanTool] = None
url_report_tool: Optional[URLReportTool] = None
vulnerability_tool: Optional[VulnerabilityTool] = None
vuln_match_tool: Optional[VulnMatchTool] = None


def get_client() -> ThreatBookClient:
    """获取微步在线威胁分析客户端实例"""
    global threatbook_client
    if threatbook_client is None:
        api_key = os.getenv("THREATBOOK_API_KEY")
        if not api_key:
            raise Exception("请设置THREATBOOK_API_KEY环境变量")
        
        config = ThreatBookConfig(api_key=api_key)
        threatbook_client = ThreatBookClient(config)
    
    return threatbook_client


def get_tools() -> Dict[str, Any]:
    """获取所有工具实例"""
    global ip_reputation_tool, ioc_detection_tool, domain_context_tool, ip_analysis_tool, domain_analysis_tool, ip_advanced_tool, domain_advanced_tool, subdomain_tool, file_analysis_tool, file_multiengines_tool, file_upload_tool, url_scan_tool, url_report_tool, vulnerability_tool, vuln_match_tool

    client = get_client()

    if ip_reputation_tool is None:
        ip_reputation_tool = IPReputationTool(client)

    if ioc_detection_tool is None:
        ioc_detection_tool = IOCDetectionTool(client)

    if domain_context_tool is None:
        domain_context_tool = DomainContextTool(client)

    if ip_analysis_tool is None:
        ip_analysis_tool = IPAnalysisTool(client)

    if domain_analysis_tool is None:
        domain_analysis_tool = DomainAnalysisTool(client)

    if ip_advanced_tool is None:
        ip_advanced_tool = IPAdvancedTool(client)

    if domain_advanced_tool is None:
        domain_advanced_tool = DomainAdvancedTool(client)

    if subdomain_tool is None:
        subdomain_tool = SubdomainTool(client)

    if file_analysis_tool is None:
        file_analysis_tool = FileAnalysisTool(client)

    if file_multiengines_tool is None:
        file_multiengines_tool = FileMultiEnginesTool(client)

    if file_upload_tool is None:
        file_upload_tool = FileUploadTool(client)

    if url_scan_tool is None:
        url_scan_tool = URLScanTool(client)

    if url_report_tool is None:
        url_report_tool = URLReportTool(client)

    if vulnerability_tool is None:
        vulnerability_tool = VulnerabilityTool(client)

    if vuln_match_tool is None:
        vuln_match_tool = VulnMatchTool(client)

    return {
        "ip_reputation": ip_reputation_tool,
        "ioc_detection": ioc_detection_tool,
        "domain_context": domain_context_tool,
        "ip_analysis": ip_analysis_tool,
        "domain_analysis": domain_analysis_tool,
        "ip_advanced": ip_advanced_tool,
        "domain_advanced": domain_advanced_tool,
        "subdomain": subdomain_tool,
        "file_analysis": file_analysis_tool,
        "file_multiengines": file_multiengines_tool,
        "file_upload": file_upload_tool,
        "url_scan": url_scan_tool,
        "url_report": url_report_tool,
        "vulnerability": vulnerability_tool,
        "vuln_match": vuln_match_tool
    }


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """列出可用的工具"""
    tools = get_tools()

    return [
        tools["ip_reputation"].get_tool_definition(),
        tools["ioc_detection"].get_tool_definition(),
        tools["domain_context"].get_tool_definition(),
        tools["ip_analysis"].get_tool_definition(),
        tools["domain_analysis"].get_tool_definition(),
        tools["ip_advanced"].get_tool_definition(),
        tools["domain_advanced"].get_tool_definition(),
        tools["subdomain"].get_tool_definition(),
        tools["file_analysis"].get_tool_definition(),
        tools["file_multiengines"].get_tool_definition(),
        tools["file_upload"].get_tool_definition(),
        tools["url_scan"].get_tool_definition(),
        tools["url_report"].get_tool_definition(),
        tools["vulnerability"].get_tool_definition(),
        tools["vuln_match"].get_tool_definition(),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str,
    arguments: Dict[str, Any]
) -> List[types.TextContent]:
    """处理工具调用"""

    tools = get_tools()

    if name == "ip_reputation":
        return await tools["ip_reputation"].execute(arguments)

    elif name == "ioc_detection":
        return await tools["ioc_detection"].execute(arguments)

    elif name == "domain_context":
        return await tools["domain_context"].execute(arguments)

    elif name == "ip_analysis":
        return await tools["ip_analysis"].execute(arguments)

    elif name == "domain_analysis":
        return await tools["domain_analysis"].execute(arguments)

    elif name == "ip_advanced":
        return await tools["ip_advanced"].execute(arguments)

    elif name == "domain_advanced":
        return await tools["domain_advanced"].execute(arguments)
    
    elif name == "subdomain":
        return await tools["subdomain"].execute(arguments)

    elif name == "file_analysis":
        return await tools["file_analysis"].execute(arguments)

    elif name == "file_multiengines":
        return await tools["file_multiengines"].execute(arguments)

    elif name == "file_upload":
        return await tools["file_upload"].execute(arguments)

    elif name == "url_scan":
        return await tools["url_scan"].execute(arguments)

    elif name == "url_report":
        return await tools["url_report"].execute(arguments)

    elif name == "vulnerability":
        return await tools["vulnerability"].execute(arguments)

    elif name == "vuln_match":
        return await tools["vuln_match"].execute(arguments)

    else:
        return [types.TextContent(
            type="text",
            text=f"未知工具: {name}"
        )]


async def main():
    """主入口函数"""
    # 配置服务器选项
    options = InitializationOptions(
        server_name="threatbook-mcp",
        server_version="0.1.0",
        capabilities=server.get_capabilities(
            notification_options=NotificationOptions(),
            experimental_capabilities={}
        )
    )
    
    try:
        logger.info("启动微步在线威胁分析MCP服务器...")
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                options
            )
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在关闭服务器...")
    except Exception as e:
        logger.error(f"服务器运行错误: {e}")
        sys.exit(1)
    finally:
        # 关闭底层 HTTP 连接
        global threatbook_client
        if threatbook_client is not None:
            try:
                await threatbook_client.aclose()
            except Exception:
                pass

