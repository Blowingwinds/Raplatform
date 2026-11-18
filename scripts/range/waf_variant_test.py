#!/usr/bin/env python
"""WAF 拦截策略变体测试 — 阶段 3 验收项。

用法（靶场须以 --waf 模式启动）：::

    python scripts/range/waf_variant_test.py --url "http://127.0.0.1:8000/products?id=1" \
        --payload "1 UNION SELECT 1,2,3" --param id --out waf_variants.json

流程：直接请求被 WAF 拦截（403）作为基线 → 用 waf_bypass.generate_variants
逐策略生成变体 → 逐次发送并记录状态码与响应摘要 → 保存 JSON 证据。

注意：绕过成功仅代表 WAF 策略存在变体空间，不作为漏洞成立证据。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

_project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_project_root))

import httpx

from src.agents.shared.waf_bypass import generate_variants

BLOCK_MARKER = "Request blocked by WAF"


async def send_attempt(client: httpx.AsyncClient, method: str, url: str,
                       headers: dict | None = None, body: str | None = None) -> dict:
    """Send one attempt and return {status, blocked, snippet}."""
    try:
        if method == "POST":
            resp = await client.post(url, headers=headers, content=body)
        else:
            resp = await client.get(url, headers=headers)
        text = resp.text
        return {
            "status": resp.status_code,
            "blocked": resp.status_code == 403 or BLOCK_MARKER in text,
            "snippet": text[:120],
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": None, "blocked": False, "snippet": f"error: {exc}"}


async def main() -> None:
    parser = argparse.ArgumentParser(description="WAF bypass variant test")
    parser.add_argument("--url", required=True, help="Full target URL with param")
    parser.add_argument("--payload", required=True, help="Payload the WAF blocks")
    parser.add_argument("--param", default=None, help="Parameter name")
    parser.add_argument("--out", default="waf_variants.json", help="Evidence output file")
    args = parser.parse_args()

    attempts: list[dict] = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        # 基线：把 payload 原样放进参数（WAF 应拦截）
        if args.param:
            base_url = re.sub(
                rf"({re.escape(args.param)}=)[^&]*",
                lambda m: m.group(1) + quote(args.payload),
                args.url,
            )
        else:
            base_url = args.url
        base = await send_attempt(client, "GET", base_url)
        attempts.append({"strategy": "baseline_direct", **base})

        variants = generate_variants(args.url, args.payload, param=args.param)
        for v in variants:
            result = await send_attempt(
                client,
                v.modified_method or "GET",
                v.modified_url,
                headers=v.modified_headers or None,
                body=v.modified_body,
            )
            attempts.append({
                "strategy": v.strategy,
                "modified_url": v.modified_url,
                "modified_payload": v.modified_payload,
                **result,
            })

    # 基线：直接 payload 已编码（对照）
    evidence = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": args.url,
        "payload": args.payload,
        "attempts": attempts,
    }
    Path(args.out).write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"{'strategy':20s} {'status':>7s} {'blocked':>8s}  snippet")
    print("-" * 70)
    for a in attempts:
        print(f"{a['strategy']:20s} {str(a['status']):>7s} {str(a['blocked']):>8s}  {a['snippet'][:50]}")
    print(f"\nEvidence saved: {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
