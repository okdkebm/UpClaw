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

__version__ = "0.1.0"
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



# 检测模块注册表（各模块的 run 函数分别以 _run_xxx 定义）
AVAILABLE = {
    "headers": _run_headers,
    "sensitive": _run_sensitive,
    "sqli": _run_sqli,
    "xss": _run_xss,
}



"""报告生成：Markdown / HTML / JSON，并归档原始证据。

UpClaw 全量开源（MIT License），报告无版本限制、无水印，可直接交付。
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
        "version": "0.1.0",
        "target": target,
        "started_at": datetime.fromtimestamp(started).astimezone().isoformat(timespec="seconds"),
        "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "duration_sec": round(time.time() - started, 2),
        "license_tier": "MIT (Open Source)",
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
        L.append("*本报告由 UpClaw 生成，遵循 MIT 开源协议，可自由用于学习与商业交付。*")
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
    checks = [c.strip() for c in (args.checks or "headers,sensitive,sqli,xss").split(",") if c.strip()]
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
        if args.verbose:
            print(f"    · {name} 完成")

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
    print(f"  开源许可    : MIT（全量开源，免费使用）")

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
    print()
    return 0


def cmd_version(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    print(f"upclaw {__version__}")
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
    s.add_argument("--checks", help="启用模块，逗号分隔（headers,sensitive,sqli,xss）")
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
