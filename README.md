# UpClaw — AI 驱动的渗透测试 CLI 工具

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)

**UpClaw** 是一款 AI 驱动的渗透测试 CLI 工具。自然语言下达目标，自动完成 **Reason→Explore→Fact→Reflect→Report** 全流程，证据级反幻觉，目标达成即收敛。

> ⚠️ **仅用于已获得明确书面授权的安全测试。** 任何未经授权的渗透行为均属违法。

---

## 特性

- **AI 驱动**：自然语言描述目标，AI 自动规划渗透路径
- **零第三方依赖**：仅使用 Python 标准库，开箱即用
- **证据级反幻觉**：每个发现都有原始请求/响应证据支撑
- **目标驱动收敛**：达成目标自动停止，不浪费资源
- **23 项渗透技能**：信息收集 6 + 漏洞验证 8 + 暴力破解 3 + Web 安全 6（详见下方能力矩阵）
- **HTML 报告**：自动生成结构化渗透测试报告

## 快速开始

```bash
# 下载单文件
curl -O https://raw.githubusercontent.com/okdkebm/UpClaw/main/upclaw.py

# 查看帮助
python upclaw.py --help

# 运行健康检查
python upclaw.py doctor

# 扫描目标
python upclaw.py scan example.com
```

### 配置 AI（可选）

```bash
cp .env.example .env
# 编辑 .env 填入你的 AI API Key
```

## 工作流

```
User Input → Reason → Explore → Fact → Reflect → Report → Done
   ↑                                                    │
   └────────────────── 循环直到达成目标 ────────────────┘
```

1. **Reason**：分析目标，制定测试计划
2. **Explore**：执行渗透测试技能
3. **Fact**：收集证据，记录发现
4. **Reflect**：分析结果，调整策略
5. **Report**：生成结构化报告
6. 目标达成则终止，否则返回 Reason 继续

## 能力矩阵

| 类别 | 技能（模块名） |
|------|------|
| 信息收集（6） | 指纹识别、端口扫描、DNS 枚举（dns）、子域名扫描（subdomain）、WAF 检测（waf）、TLS/HTTPS 检查（tls） |
| 漏洞验证（8） | SQL 注入（sqli）、XSS（xss）、命令注入（cmdi）、SSRF（ssrf）、XXE（xxe）、本地文件包含/路径遍历（lfi）、开放重定向（open-redirect）、CRLF 注入（crlf） |
| 暴力破解（3） | 目录爆破（dir）、备份文件扫描（backup）、参数模糊测试（fuzz） |
| Web 安全（6） | CORS 配置（cors）、Cookie 安全（cookie）、HTTP 方法（methods）、WebDAV（webdav）、安全响应头（headers）、敏感路径（sensitive） |

## 许可

本项目采用 **Apache-2.0 License** 开源。

- 个人学习、研究、CTF 竞赛：免费
- 商业使用：需购买商业授权
- 详见 [网站许可页](website/legal.html)

## 法律声明

UpClaw **仅可用于已获得明确书面授权的安全测试、CTF 竞赛、安全教学和红队演练**。使用者应自行确保拥有目标系统的测试授权，并承担全部法律责任。

## 作者

- 作者：懰襬
- QQ 交流群：917335721