# UpClaw — AI 驱动的渗透测试 CLI 工具

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![Zero Dep](https://img.shields.io/badge/dependencies-zero-green)](https://github.com/okdkebm/UpClaw)
[![English README](https://img.shields.io/badge/docs-English-blue)](README.md)

**UpClaw** 是一款 AI 驱动的渗透测试 CLI 工具：自然语言下达目标，自动完成 **Reason→Explore→Fact→Reflect→Report** 全流程；**单文件、零第三方依赖**，证据级反幻觉，目标达成即收敛。

> ⚠️ **仅用于已获得明确书面授权的安全测试。** 任何未经授权的渗透行为均属违法。

> 国际版：[English README](README.md)

***

## 特性

- **AI 驱动**：自然语言描述目标，AI 自动规划渗透路径

- **零第三方依赖**：核心仅使用 Python 标准库，一个文件开箱即用

- **证据级反幻觉**：每个发现都有原始请求/响应证据支撑，报告可逐条溯源

- **目标驱动收敛**：达成目标自动停止，不浪费资源

- **31 项渗透技能**：信息收集 6 + 漏洞验证 10 + 暴力破解 3 + Web 安全 12（详见下方能力矩阵）

- **外置工具适配层**：自动检测并驱动本机已装的 nuclei/nmap/sqlmap/nikto/ffuf/dirsearch/subfinder/httpx/ZAP/wpscan/commix/hydra/masscan/gobuster/arjun/gau 等 16 个工具，结果统一归一化进入报告

- **证据轨迹**：scan 输出 `trace.json` 时间线回放 + 报告内「执行轨迹」表，适合客户审计溯源与 AI 二次分析

- **手动工具链（v0.4）**：Burp 式手动三件套 `req`（改包重放）/ `codec`（编解码）/ `cmp`（响应对比），靶场手测无需另开 GUI 工具

## 与主流工具对比

| | UpClaw | Burp Suite Pro | Nuclei | xray |
|---|--------|---------------|--------|------|
| **许可** | Apache-2.0 免费 | ~$449/年 | MIT | 商业 |
| **依赖** | **零（纯标准库）** | JVM | Go 二进制 | Go 二进制 |
| **形态** | **单个 .py 文件** | 安装包 | 二进制+模板 | 二进制 |
| **AI 规划循环** | 内置（Reason→Report） | 无 | 无 | 无 |
| **证据级报告** | HTML/MD/JSON + **trace.json 回放** | 部分 | JSON | JSON |
| **零依赖内置检测** | **29 个模块** | 付费扩展 | 需模板 | ✓ |
| **外置工具编排** | 驱动 **16 个工具** | 手动 | - | - |
| **手动三件套** | `req`/`codec`/`cmp` | 仅 Pro | 无 | 无 |

## 快速开始

```bash
# 下载单文件（零安装）
curl -O https://raw.githubusercontent.com/okdkebm/UpClaw/master/upclaw.py

# 查看帮助 / 健康检查 / 工具检测
python upclaw.py --help
python upclaw.py doctor
python upclaw.py tools

# 扫描目标（自动调用已安装的外部工具）
python upclaw.py scan example.com

# 非交互 + 授权文件
python upclaw.py scan example.com --auth-file auth.json

# 手动三件套（靶场手测，无需 GUI）
python upclaw.py req "http://靶场/sqli/?id=1'" -m "SQL syntax"
echo "id%3D1%27" | python upclaw.py codec decode url
python upclaw.py cmp "http://靶场/sqli/?id=1" "http://靶场/sqli/?id=1' AND '1'='2"
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
| 漏洞验证（10）  | SQL 注入（sqli）、XSS（xss）、命令注入（cmdi）、SSRF（ssrf）、XXE（xxe）、本地文件包含/路径遍历（lfi）、开放重定向（open-redirect）、CRLF 注入（crlf）、模板注入（ssti）、GraphQL introspection（graphql） |
| 暴力破解（3）   | 目录爆破（dir）、备份文件扫描（backup）、参数模糊测试（fuzz）                                                                    |
| Web 安全（12） | CORS 配置（cors）、Cookie 安全（cookie）、HTTP 方法（methods）、WebDAV（webdav）、安全响应头（headers）、敏感路径（sensitive）、点击劫持（clickjacking）、CSRF（csrf）、Host 头注入（host-header）、CMS/框架指纹（cms）、子域接管（takeover）、JS 密钥猎手（js-secrets）           |

以上全部模块均纯 Python 标准库实现——即使机器上一个外部安全工具都没装，UpClaw 依然可独立完成完整扫描。

## 外置工具适配层

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
| wpscan            | WordPress 专扫 | JSON 解析，含插件/漏洞/用户枚举     |
| commix            | 命令注入专扫   | 需 URL 带查询参数；实弹验证注入点      |
| hydra             | 服务口令爆破   | 需 config 配置口令字典（userlist/passlist） |
| masscan           | 高速端口扫描   | 全量 1-65535 端口（需 root/管理员） |
| gobuster          | 目录/子域爆破  | 需字典；输出 200/401/403 等状态    |
| arjun             | HTTP 参数发现  | 发现未文档化隐藏参数               |
| gau               | 历史 URL 采集   | Wayback/CommonCrawl/OTX 档案回溯  |

检测与状态：`upclaw tools` 查看全部 21 项工具的检测结果（含 Yakit、BeEF、Burp Suite、AppScan、ARL 的识别与人工/API 驱动提示）。

> 外部工具按其各自开源/商业许可独立分发，UpClaw 仅做驱动与结果归一化；未安装时自动跳过，不影响核心零依赖能力。使用 `--no-ext` 关闭该阶段，`--ext-tools nuclei,sqlmap` 只启用指定工具；ffuf/gobuster 字典可用 `config set wordlist <路径>` 配置；hydra 口令字典用 `config set ext_hydra_userlist <路径>` / `config set ext_hydra_passlist <路径>` 配置。Nuclei 支持定向扫描：`--nuclei-tags cve,wordpress` / `--nuclei-severity high,critical` / `--nuclei-template <文件>`。

## 证据轨迹（v0.6）

每次 `scan` 除 HTML/MD/JSON 报告外，额外输出 **`trace.json`**——按时间序回放每条发现的完整决策链（步骤号/时间/严重级/请求/证据/影响/修复建议），报告内同步提供"执行轨迹"时间线表格。适用于：

- 客户对审计过程的逐条溯源（每步都有原始证据支撑）
- AI 二次分析：把 `trace.json` 喂给大模型做攻击链推理与复测规划
- 团队复核：按时间线核对扫描是否覆盖了所有关键面

## Roadmap（规划中）

- **任务树方法论**：扫描发现 → 动态规划下一步验证/利用（参考 PentestGPT 的任务推理）
- **多 Agent 分工**：recon / 扫描 / 利用 / 报告分角色协作（复用 AGI 沙盒 7-Agent 架构）
- **内置轻量 PoC 库**：参照 nuclei 单模板结构，沉淀高频 CVE 的零依赖验证模板

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

## 支持一下

如果 UpClaw 帮你省了时间、或让你学到了东西——**点一个 star 就是最好的感谢，也能帮助更多人发现这个项目。** ⭐

- 欢迎提交 Issue、功能建议与 PR（见 [SECURITY.md](SECURITY.md)）
- 交流群：QQ 917335721

## 许可

本项目采用 **Apache-2.0 License** 开源。

- 个人学习、研究、CTF 竞赛：免费

- 商业使用：需购买商业授权

- 详见 [网站许可页](website/legal.html)

## 法律声明

UpClaw **仅可用于已获得明确书面授权的安全测试、CTF 竞赛、安全教学和红队演练**。使用者应自行确保拥有目标系统的测试授权，并承担全部法律责任。

## 作者

- 作者：懰襬
