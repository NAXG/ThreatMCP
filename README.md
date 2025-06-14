# 微步在线威胁分析完整API MCP 服务器

这是一个基于微步在线威胁分析API的MCP（Model Context Protocol）服务器，提供完整的情报查询功能。支持微步在线威胁分析API的全部15个工具，包括IP分析、域名分析、文件检测、URL扫描、漏洞情报等。

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![MCP Protocol](https://img.shields.io/badge/MCP-1.9.3-green.svg)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![微步在线威胁分析API](https://img.shields.io/badge/微步在线威胁分析API-完整支持-red.svg)](https://x.threatbook.com)

## 功能特性

### IP分析
- 🔍 **IP信誉查询**: 查询IP地址的安全信誉信息
- 🌍 **IP分析**: 获取IP地理位置、ASN信息、威胁类型等
- 📈 **IP高级查询**: 获取IP历史解析记录、端口信息等

### 域名分析
- 🌐 **域名分析**: 获取域名解析IP、Whois信息、威胁类型等
- 📊 **域名高级查询**: 获取域名历史Whois、历史解析IP信息
- 🔍 **域名上下文查询**: 针对恶意域名查询上下文信息
- 🌿 **子域名查询**: 获取域名的子域名信息

### 文件分析
- 📄 **文件信誉报告**: 获取文件详细的静态和动态分析报告
- 🔬 **反病毒引擎检测**: 获取文件经过22款反病毒扫描引擎检测结果
- 📤 **文件上传分析**: 上传文件进行沙箱分析

### URL分析
- 🌐 **URL扫描**: 对URL进行扫描分析
- 📋 **URL信誉报告**: 获取URL扫描引擎检测结果

### 漏洞情报
- 🛡️ **漏洞情报**: 获取公开漏洞的基础信息、风险评估、PoC等
- 🎯 **产品漏洞匹配**: 通过厂商产品匹配功能聚合相关漏洞

### 失陷检测
- 🚨 **IOC检测**: 检测IP地址或域名的恶意威胁

## 🚀 快速开始

### 1. 安装依赖

```bash
# 进入项目目录
cd ThreatMCP

# 安装依赖（自动生成的精确依赖）
pip install -r requirements.txt
```

**当前依赖包：**
- `mcp` - Model Context Protocol核心包
- `pydantic` - 数据验证库
- `requests` - HTTP请求库

### 2. 配置API密钥

设置微步在线威胁分析API密钥环境变量：

```bash
export THREATBOOK_API_KEY="your_threatbook_api_key_here"
```

### 3. 获取微步在线威胁分析API密钥

1. 访问 [微步在线威胁分析官网](https://x.threatbook.com)
2. 注册账号并登录
3. 在API管理页面获取你的API密钥



### 4. 启动服务器

## 🔗 集成使用

### Claude Desktop集成

在Claude Desktop的配置文件中添加：

```json
{
  "mcpServers": {
    "threatbook": {
      "command": "python",
      "args": ["/path/to/your/ThreatMCP/run_server.py"],
      "env": {
        "THREATBOOK_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

**配置说明：**
- `command`: 使用 `python` 命令
- `args`: 使用完整绝对路径运行 `run_server.py` 脚本
- `env`: 设置微步在线威胁分析API密钥环境变量

**注意**: 请将路径 `/path/to/your/ThreatMCP/run_server.py` 替换为您实际的项目路径

### 其他MCP客户端

本服务器兼容所有支持MCP协议的客户端，包括：
- Claude Desktop
- 其他AI助手工具
- 自定义MCP客户端

## 🔍 实战应用场景(遐想)

### AI 驱动的 Linux 系统应急响应分析

结合 AI SSH 工具和威胁情报，可以实现智能化的 Linux 系统安全应急分析：

#### 🚨 典型应急响应流程

**1. 异常发现阶段**
```bash
# AI 通过 SSH 连接到可疑系统
ssh user@suspicious-server

# 检查系统基本状态
ps aux | grep -E "(bitcoin|mining|crypto)"
netstat -tulpn | grep LISTEN
```

**2. 威胁情报关联分析**
- **可疑 IP 分析**: 使用 `ip_reputation` 和 `ip_analysis` 工具分析系统中发现的外部连接 IP
- **域名威胁检测**: 通过 `domain_analysis` 检查系统 DNS 查询记录中的可疑域名
- **文件哈希验证**: 使用 `file_analysis` 分析可疑文件的 MD5/SHA256 哈希值

**3. 深度分析示例**

```bash
# 发现可疑外连 IP: 192.168.1.100
# AI 自动调用威胁情报 API 进行分析
```

AI 会自动：
1. 调用 `ip_reputation` 查询该 IP 的信誉信息
2. 使用 `ip_analysis` 获取 IP 地理位置、ASN、历史威胁记录
3. 通过 `ioc_detection` 检测是否为已知的失陷指标

**4. 综合威胁评估**

AI 结合系统信息和威胁情报，提供：
- 🎯 **威胁等级评估**: 基于多维度情报数据
- 📊 **攻击链分析**: 关联分析攻击者的 TTPs
- 🛡️ **处置建议**: 提供具体的安全加固措施

#### 🔧 支持的分析场景

| 分析类型 | 使用的威胁情报工具 | 应用场景 |
|---------|------------------|----------|
| **网络连接分析** | `ip_reputation`, `ip_analysis` | 检测恶意外连、C&C 通信 |
| **DNS 查询分析** | `domain_analysis`, `domain_context` | 发现恶意域名、DGA 域名 |
| **文件完整性检查** | `file_analysis`, `file_multiengines` | 检测木马、后门、挖矿程序 |
| **Web 访问分析** | `url_scan`, `url_report` | 分析可疑 URL 访问记录 |
| **漏洞风险评估** | `vulnerability`, `vuln_match` | 系统漏洞风险评估 |

#### 💡 智能化优势

- **自动化分析**: AI 自动执行系统检查和威胁情报查询
- **关联分析**: 将系统日志与全球威胁情报进行关联
- **实时响应**: 快速识别威胁并提供处置建议
- **知识积累**: 基于历史案例不断优化分析策略

#### 🎯 实际应用价值

1. **提升响应速度**: 从小时级缩短到分钟级
2. **降低误报率**: 基于权威威胁情报源进行验证
3. **标准化流程**: 确保应急响应的一致性和完整性
4. **知识传承**: AI 助手可以传承专家经验

> **注意**: 此功能需要配合支持 SSH 的 AI 工具使用，如 Claude Desktop 配合 SSH MCP 服务器等。

## 🛠️ 完整API工具集

本MCP服务器提供微步在线威胁分析API的**完整15个工具**，覆盖所有威胁情报分析场景：

### IP相关工具

1. **ip_reputation** - IP信誉查询
2. **ip_analysis** - IP分析
3. **ip_advanced** - IP高级查询
4. **ioc_detection** - 失陷检测

### 域名相关工具

5. **domain_analysis** - 域名分析
6. **domain_advanced** - 域名高级查询
7. **domain_context** - 域名上下文查询
8. **subdomain** - 子域名查询

### 文件相关工具

9. **file_analysis** - 文件信誉报告
10. **file_multiengines** - 文件反病毒引擎检测
11. **file_upload** - 提交文件分析

### URL相关工具

12. **url_scan** - 提交URL分析
13. **url_report** - URL信誉报告

### 漏洞相关工具

14. **vulnerability** - 漏洞情报
15. **vuln_match** - 产品漏洞匹配



## 🏗️ 项目架构


### 项目结构

```
ThreatMCP/
├── threatbook_mcp/              # 核心包目录
│   ├── __init__.py              # 包初始化
│   ├── server.py                # MCP服务器核心
│   ├── response_handler.py      # 统一响应处理
│   ├── ip_reputation.py         # IP信誉查询
│   ├── ip_analysis.py           # IP分析
│   ├── ip_advanced.py           # IP高级查询
│   ├── ioc_detection.py         # 失陷检测
│   ├── domain_analysis.py       # 域名分析
│   ├── domain_advanced.py       # 域名高级查询
│   ├── domain_context.py        # 域名上下文查询
│   ├── subdomain.py             # 子域名查询
│   ├── file_analysis.py         # 文件信誉报告
│   ├── file_multiengines.py     # 文件反病毒检测
│   ├── file_upload.py           # 文件上传分析
│   ├── url_scan.py              # URL扫描
│   ├── url_report.py            # URL信誉报告
│   ├── vulnerability.py         # 漏洞情报
│   └── vuln_match.py            # 产品漏洞匹配
├── run_server.py                # 🚀 服务器启动脚本（主入口）
├── requirements.txt             # 项目依赖
├── README.md                    # 项目说明
└── config_example.json          # Claude Desktop配置示例
```

## 许可证

MIT License

## 支持

如有问题或建议，请提交Issue或联系开发者。