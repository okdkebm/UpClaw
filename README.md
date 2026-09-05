# UpClaw

> AI-driven penetration testing CLI — one single-file, zero-dependency Python script.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![Zero Dep](https://img.shields.io/badge/dependencies-zero-green)](https://github.com/okdkebm/UpClaw)
[![中文文档](https://img.shields.io/badge/docs-%E4%B8%AD%E6%96%87-important)](README.zh-CN.md)

**Describe the target in plain language. UpClaw autonomously runs the full
Reason → Explore → Fact → Reflect → Report loop — evidence-backed, hallucination-resistant,
and it stops when the goal is met.**

```
$ python upclaw.py scan example.com --auth-file auth.json

[*] HTTP fingerprint → Server: nginx  tech: [WordPress 6.1]
[*] Phase 3/3 security checks...
    · ssti done · takeover done · js-secrets done
✓ Verified findings: HIGH=3  MEDIUM=4  LOW=2
Report: reports/report.html (+ trace.json replay)
```

> ⚠️ **For authorized security testing only.** Scanning systems without written
> authorization is illegal in most jurisdictions.

[中文文档（Chinese README）](README.zh-CN.md)

---

## Why UpClaw?

| | UpClaw | Burp Suite Pro | Nuclei | xray |
|---|--------|---------------|--------|------|
| **License** | Apache-2.0, free | ~$449/yr | MIT | proprietary |
| **Dependencies** | **zero (pure stdlib)** | JVM | Go binary | Go binary |
| **Delivery** | **one .py file** | installer | binary + templates | binary |
| **AI agent loop** | built-in (Reason→Report) | no | no | no |
| **Evidence-grade report** | HTML/MD/JSON + **trace.json replay** | partial | JSON | JSON |
| **Zero-dep built-in checks** | **29 modules** | paid ext | via templates | ✓ |
| **External tool orchestration** | drives **16 tools** | manual | n/a | n/a |
| **Manual toolkit (Repeater/Decoder/Comparer)** | `req` / `codec` / `cmp` | Pro only | no | no |

**UpClaw is the only one that combines: AI planning + zero-dependency single file +
evidence-chain reports + Burp-style manual tools — all in one script.**

---

## Quick start

```bash
# Single file, nothing to install
curl -O https://raw.githubusercontent.com/okdkebm/UpClaw/master/upclaw.py

python upclaw.py --help     # help
python upclaw.py doctor     # health check
python upclaw.py tools      # detect installed external tools

# Full scan (auto-drives any installed external tools)
python upclaw.py scan example.com

# Non-interactive with authorization file
python upclaw.py scan example.com --auth-file auth.json

# Manual toolkit (targeted testing, no GUI needed)
python upclaw.py req "http://host/sqli/?id=1'" -m "SQL syntax"
echo "id%3D1%27" | python upclaw.py codec decode url
python upclaw.py cmp "http://host/sqli/?id=1" "http://host/sqli/?id=1' AND '1'='2"
```

## What it detects — 31 built-in skills (zero-dependency)

| Category | Modules |
|---|---|
| **Recon (6)** | fingerprint, ports, dns, subdomain, waf, tls |
| **Vuln validation (10)** | sqli, xss, cmdi, ssrf, xxe, lfi, open-redirect, crlf, **ssti**, **graphql** |
| **Brute (3)** | dir, backup, fuzz |
| **Web security (12)** | cors, cookie, methods, webdav, headers, sensitive, clickjacking, csrf, host-header, cms, **takeover**, **js-secrets** |

Everything above is pure Python stdlib — it works on any box with Python 3.10+,
even with no external security tools installed.

## Drives your existing toolbox (16 tools)

UpClaw auto-detects installed tools and normalizes their output into one report:

`nuclei` · `nmap` · `sqlmap` · `nikto` · `ffuf` · `dirsearch` · `subfinder` · `httpx` ·
`zap` · `wpscan` · `commix` · `hydra` · `masscan` · `gobuster` · `arjun` · `gau`

Directional Nuclei scans: `--nuclei-tags wordpress,cve --nuclei-severity high`.

## Evidence trail & report

Every finding carries its raw request/response as proof. Each `scan` additionally
writes **`trace.json`** — a timestamped replay of the full decision chain
(step / request / evidence / impact / remediation) plus a timeline table in the report:

- Trace every finding back to source for client audits
- Feed `trace.json` back to an LLM for attack-chain reasoning and re-test planning

## Roadmap

- Task-tree methodology: dynamically plan the next step from scan findings
- Multi-agent division: recon / scan / exploit / report roles
- Built-in lightweight PoC library (nuclei-style templates, zero-dep)

---

## Star it?

If UpClaw saved you time or taught you something — **a star is the easiest way to
say thanks and helps more people discover it.** ⭐

- Bug reports, feature ideas and PRs are very welcome (see [SECURITY.md](SECURITY.md)).
- Community / discussion: join the QQ group 917335721.

## License

**Apache-2.0**. Free for learning, research and CTF. Commercial use requires a
commercial license — see [website/legal.html](website/legal.html).

## Legal

UpClaw is for **authorized security testing, CTF, security education and red-team
exercises only**. You are responsible for obtaining permission for every target you test.
