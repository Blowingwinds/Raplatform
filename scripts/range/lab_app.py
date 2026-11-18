#!/usr/bin/env python
"""Raplatform 受控靶场 — intentionally vulnerable FastAPI lab (local only).

故意保留的漏洞（仅用于本机验收）：

  GET /products?id=N            SQL 注入（SQLite 字符串拼接，id 未参数化）
  GET /search?q=...             反射型 XSS（输出未转义）
  GET /exec?cmd=...             命令注入（受控 RCE 验证点，回显执行结果）
  GET /admin                    Header 认证绕过候选（X-Admin: 1 即放行）
  GET /                         指纹诱饵（X-Powered-By: PHP/7.4.3 + Struts 注释）
  GET /version                  组件版本诱饵（fingerprint 素材）

可选 WAF（--waf 开启）：黑名单中间件拦截明显 payload 模式并记录，
记录通过 GET /waf-log 查看（供 WAF 策略变体测试用）。

用法::

    python scripts/range/lab_app.py [--host 127.0.0.1] [--port 8000] [--waf]
"""

from __future__ import annotations

import argparse
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

app = FastAPI(title="Raplatform Local Lab", docs_url=None, redoc_url=None)

# ── 数据库（内存 + 种子数据） ────────────────────────────────────────────

_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
_conn.executemany(
    "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
    [
        (1, "Widget", 9.99),
        (2, "Gadget", 19.99),
        (3, "Doohickey", 4.49),
        (4, "Thingamabob", 29.99),
        (5, "Secret Flag", 1337.0),
    ],
)
_conn.commit()

# ── WAF 模拟层（可选） ───────────────────────────────────────────────────

_WAF_PATTERNS = [
    "union select",
    "or 1=1",
    "' or ",
    "sleep(",
    "information_schema",
    "<script",
    "cmd=",
    "cat /etc",
    "whoami",
    "id;",
    "bash -c",
]

_waf_log: list[dict] = []


class _WafMiddleware:
    """Naive blacklist WAF — blocks obvious payload patterns, logs attempts."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_query = scope.get("query_string", b"").decode(errors="replace")
        # 解码一次再匹配（贴近真实 WAF；双重编码可穿过本层）
        decoded = unquote(raw_query)
        request_line = f"{scope.get('path', '')}?{decoded}"

        for pattern in _WAF_PATTERNS:
            if pattern in request_line.lower():
                _waf_log.append({
                    "time": datetime.now(timezone.utc).isoformat(),
                    "request": request_line,
                    "blocked_by": pattern,
                })
                response = Response(
                    content="<h1>403 Forbidden</h1><p>Request blocked by WAF.</p>",
                    status_code=403,
                    headers={"content-type": "text/html"},
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)


# ── 路由 ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <html><head><title>Raplatform Local Lab</title></head>
    <body>
      <h1>Local Lab Shop</h1>
      <!-- Generator: Apache Struts 2.5.30 -->
      <p>See <a href="/products?id=1">products</a>.</p>
    </body></html>
    """


@app.get("/products")
def products(id: str = "1"):
    """故意使用字符串拼接构造 SQL（可注入）。"""
    # SQLi: id 直接拼进查询
    query = f"SELECT id, name, price FROM products WHERE id = {id}"
    try:
        rows = _conn.execute(query).fetchall()
    except sqlite3.Error:
        return JSONResponse({"error": "bad query"}, status_code=500)
    return {"query": query, "rows": [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]}


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    """反射型 XSS：q 未转义直接回显。"""
    return f"<html><body><h1>Search results for: {q}</h1></body></html>"


@app.get("/exec")
def exec_cmd(cmd: str = ""):
    """命令注入：cmd 直接交给 shell 执行（受控 RCE 验证点）。"""
    if not cmd:
        return {"error": "missing cmd"}
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
    except subprocess.TimeoutError:
        return {"error": "timeout"}
    return {
        "cmd": cmd,
        "stdout": proc.stdout.decode(errors="replace"),
        "stderr": proc.stderr.decode(errors="replace"),
        "returncode": proc.returncode,
    }


@app.get("/admin")
def admin(request: Request):
    """Header 认证绕过候选：X-Admin: 1 即放行。"""
    if request.headers.get("x-admin") != "1":
        return Response("401 Unauthorized — admin only", status_code=401)
    return HTMLResponse("<h1>Admin Panel</h1><p>flag{local-lab-admin-bypass}</p>")


@app.get("/version")
def version():
    """指纹诱饵：宣称的组件版本（与实际栈无关，供 tech-detect 练习）。"""
    return {
        "app": "local-lab",
        "server": "nginx/1.18.0",
        "framework": "Django/2.2.24",
        "database": "MySQL/5.7.32",
    }


@app.get("/waf-log")
def waf_log():
    return {"blocked": len(_waf_log), "entries": _waf_log[-20:]}


@app.get("/phpinfo.php", response_class=HTMLResponse)
def phpinfo_decoy():
    """暴露类诱饵：伪造 phpinfo 页面（nuclei exposures 模板候选）。"""
    return (
        "<html><head><title>phpinfo()</title></head><body>"
        "<h1>PHP Version 7.4.3</h1>"
        "<p>System: Windows NT LAB 10.0</p>"
        "<p>disable_functions: no value</p>"
        "</body></html>"
    )


@app.get("/.git/config")
def git_config_decoy():
    """暴露类诱饵：伪造 .git/config（nuclei exposures 模板候选）。"""
    return (
        "[core]\n"
        "    repositoryformatversion = 0\n"
        "    filemode = false\n"
        "[remote \"origin\"]\n"
        "    url = https://example.com/lab-repo.git\n"
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.middleware("http")
async def _set_fingerprint_headers(request: Request, call_next):
    """指纹诱饵头 + CORS 反射（cors 误配置模板候选）。"""
    response = await call_next(request)
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


# ── 入口 ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Raplatform local vulnerable lab")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--waf", action="store_true", help="Enable naive WAF middleware")
    args = parser.parse_args()

    if args.waf:
        app.add_middleware(_WafMiddleware)
        print(f"[lab] WAF enabled — blocked attempts visible at /waf-log")

    print(f"[lab] Vulnerable lab starting at http://{args.host}:{args.port}")
    print("[lab] Endpoints: /products?id=N (SQLi) | /search?q= (XSS) | "
          "/exec?cmd= (RCE) | /admin (auth bypass) | /version")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
