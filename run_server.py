#!/usr/bin/env python3
"""微步在线威胁分析MCP服务器启动脚本"""

import asyncio


from threatbook_mcp.server import main

if __name__ == "__main__":
    asyncio.run(main())
