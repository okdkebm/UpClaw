---
name: upclaw
description: |
  UpClaw — AI 驱动的渗透测试 CLI 工具。自然语言描述目标，自动完成渗透测试全流程。
  核心能力：(1) 自然语言下达渗透目标 (2) 自动执行 Reason→Explore→Fact→Reflect→Report 全流程
  (3) 证据级反幻觉，每个发现都有原始请求/响应证据 (4) 目标驱动收敛，达成目标自动停止
  (5) 23 项渗透技能覆盖信息收集、漏洞验证、暴力破解、Web 安全等 (6) 零第三方依赖，纯 Python 标准库
  (7) 自动生成 HTML 报告。
  注意：仅用于已获得明确书面授权的安全测试，禁止未授权扫描。
---

# UpClaw — AI 驱动的渗透测试 CLI 工具

## 概述

UpClaw 是一款 AI 驱动的渗透测试命令行工具。用户通过自然语言描述目标，工具自动完成从信息收集到漏洞验证再到报告生成的全流程。采用证据级反幻觉机制，确保每个发现都有原始证据支撑。

## 工作流

```
User Input → Reason → Explore → Fact → Reflect → Report → Done
   ↑                                                    │
   └────────────────── 循环直到达成目标 ────────────────┘
```

## 能力矩阵

### 信息收集
- DNS 枚举、子域名扫描、端口扫描、WAF 检测、指纹识别

### 漏洞验证
- SQL 注入、XSS、命令注入、SSRF、XXE、文件包含、路径遍历

### 暴力破解
- 目录爆破、备份文件扫描、参数模糊测试

### Web 安全
- CORS 检查、HTTPS 检查、Cookie 安全、CSP 评估

### 高级利用
- 原型污染、CRLF 注入、Open Redirect、WebDav 测试

## 使用方法

```bash
# 查看帮助
python upclaw.py --help

# 运行健康检查
python upclaw.py doctor

# 扫描目标
python upclaw.py scan example.com

# 查看版本
python upclaw.py --version
```

## 配置

工具支持通过环境变量或配置文件设置 AI 推理参数：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `PROVIDER` | AI 提供商 | 空（跳过 AI 功能） |
| `BASE_URL` | API 地址 | 空 |
| `API_KEY` | API 密钥 | 空 |
| `MODEL` | 模型名称 | 空 |
| `TIMEOUT` | 请求超时（秒） | 6 |
| `THREADS` | 并发线程数 | 16 |

## 输出

- 扫描结果以结构化 HTML 报告形式输出
- 默认输出目录：`reports/`
- 支持自定义输出格式和路径

## 许可

Apache-2.0 License。个人学习免费，商业使用需购买授权。

## 法律声明

仅用于已获得明确书面授权的安全测试、CTF 竞赛、安全教学和红队演练。