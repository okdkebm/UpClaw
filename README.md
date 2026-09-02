# UpClaw — AI 驱动的渗透测试 CLI 工具

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)

**UpClaw** 是一款 AI 驱动的渗透测试 CLI 工具。自然语言下达目标，自动完成 **Reason→Explore→Fact→Reflect→Report** 全流程，证据级反幻觉，目标达成即收敛。

> ⚠️ **仅用于已获得明确书面授权的安全测试。** 任何未经授权的渗透行为均属违法。

***

## 特性

- **AI 驱动**：自然语言描述目标，AI 自动规划渗透路径

- **零第三方依赖**：核心仅使用 Python 标准库，开箱即用

- **证据级反幻觉**：每个发现都有原始请求/响应证据支撑

- **目标驱动收敛**：达成目标自动停止，不浪费资源

- **23 项渗透技能**：信息收集 6 + 漏洞验证 8 + 暴力破解 3 + Web 安全 6（详见下方能力矩阵）

- **外置工具适配层（v0.3）**：自动检测本机已装的 nuclei/nmap/sqlmap/nikto/ffuf/dirsearch/subfinder/httpx/ZAP 等工具，扫描时自动调用，结果统一归一化进入报告；并检测 Yakit/BeEF/Burp/AppScan/ARL

- **HTML 报告**：自动生成结构化渗透测试报告

- **手动工具链（v0.4）**：Burp 式手动三件套 `req`（改包重放）/ `codec`（编解码）/ `cmp`（响应对比），靶场手测无需另开 GUI 工具

## 快速开始

```bash
# 下载单文件
curl -O https://raw.githubusercontent.com/okdkebm/UpClaw/main/upclaw.py

# 查看帮助
python upclaw.py --help

# 运行健康检查
python upclaw.py doctor

# 查看已检测到的外部工具
python upclaw.py tools

# 扫描目标（自动调用已安装的外部工具）
python upclaw.py scan example.com

# 跳过外部工具阶段 / 只启用指定外部工具
python upclaw.py scan example.com --no-ext
python upclaw.py scan example.com --ext-tools nuclei,sqlmap
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

| 类别        | 技能（模块名）                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------- |
| 信息收集（6）   | 指纹识别、端口扫描、DNS 枚举（dns）、子域名扫描（subdomain）、WAF 检测（waf）、TLS/HTTPS 检查（tls）                                     |
| 漏洞验证（8）   | SQL 注入（sqli）、XSS（xss）、命令注入（cmdi）、SSRF（ssrf）、XXE（xxe）、本地文件包含/路径遍历（lfi）、开放重定向（open-redirect）、CRLF 注入（crlf） |
| 暴力破解（3）   | 目录爆破（dir）、备份文件扫描（backup）、参数模糊测试（fuzz）                                                                    |
| Web 安全（6） | CORS 配置（cors）、Cookie 安全（cookie）、HTTP 方法（methods）、WebDAV（webdav）、安全响应头（headers）、敏感路径（sensitive）           |

## 外置工具适配层（v0.3）

UpClaw 会自动检测本机已安装的安全工具，扫描时自动调用并把结果归一化为 UpClaw 发现（证据优先，统一进入报告）：

| 工具                | 能力        | 说明                       |
| ----------------- | --------- | ------------------------ |
| nuclei            | 模板化漏洞扫描   | 命中即验证（VERIFIED），含 CVE 引用 |
| nmap              | 端口/服务识别   | XML 解析，输出开放端口与服务版本       |
| sqlmap            | SQL 注入验证  | 需 URL 带查询参数；实弹验证注入点      |
| nikto             | Web 启发式扫描 | 结果标记 UNVERIFIED，需人工复核    |
| ffuf / dirsearch  | 目录枚举      | 自动校准降低误报；ffuf 需配置字典      |
| subfinder / httpx | 资产发现      | 子域名枚举与存活/技术栈探测           |
| OWASP ZAP         | Web 主动扫描  | 需安装 zap-baseline.py 入口   |

检测与状态：`upclaw tools` 查看全部 14 项工具的检测结果（含 Yakit、BeEF、Burp Suite、AppScan、ARL 的识别与人工/API 驱动提示）。

> 外部工具按其各自开源/商业许可独立分发，UpClaw 仅做驱动与结果归一化；未安装时自动跳过，不影响核心零依赖能力。使用 `--no-ext` 关闭该阶段，`--ext-tools nuclei,sqlmap` 只启用指定工具；ffuf 字典可用 `config set wordlist <路径>` 配置。

## 手动工具链（v0.4）

Burp Suite 式的手动测试三件套，纯标准库实现、零依赖。靶场手测与 AI 自动扫描互补：扫描器负责广度，手动三件套负责「改包 → 重放 → 对比」的精细验证。

| 命令        | 等价物            | 用途                                      |
| --------- | -------------- | --------------------------------------- |
| `req`     | Burp Repeater  | 自定义方法/请求头/请求体重放，`-m` 关键词命中检测（判断漏洞特征是否出现） |
| `codec`   | Burp Decoder   | url / base64 / hex / html 双向编解码，支持 stdin 管道 |
| `cmp`     | Burp Comparer  | 双请求响应对比：头部差异 + 正文 unified diff + 相似度，判越权/注入生效 |

```bash
# 手测 SQLi：改包重放 + 检测报错特征（模拟靶场 Repeater 工作流）
upclaw req "http://靶场/sqli/?id=1' AND 1=1-- -" -H "Cookie: PHPSESSID=xxx; security=low" -m "SQL syntax" -m "Unknown column"

# 解码注入 payload
echo "id%3D1%27%20AND%201%3D1" | upclaw codec decode url

# 对比正常 / 注入响应差异，判断注入是否生效
upclaw cmp "http://靶场/sqli/?id=1" "http://靶场/sqli/?id=1' AND 1=1-- -"
```

核心思路：**手动定位 → 工具验证 → 不看工具输出你就输了**。先用 `req` 手测发现异常，再用 `cmp` 确认差异，最后才交给自动扫描器（sqlmap/nuclei）收尾。

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

