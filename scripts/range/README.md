# Raplatform 受控靶场（Local Lab）

本目录是本机验收用的受控靶场：一个故意带漏洞的 FastAPI 应用，仅供
`127.0.0.1` 本地验收，**不要对公网或他人系统运行**。

## 启动

```powershell
# 无 WAF
python scripts/range/lab_app.py --port 8000

# 带 WAF 模拟层（验收 WAF 策略变体测试时使用）
python scripts/range/lab_app.py --port 8000 --waf
```

## 漏洞点

| 端点 | 漏洞 | 预期效果 |
|------|------|----------|
| `GET /products?id=1` | SQL 注入（SQLite 字符串拼接） | `id=1 OR 1=1` / `id=0 UNION SELECT ...` 返回全部行 |
| `GET /search?q=<script>alert(1)</script>` | 反射型 XSS | 脚本原样回显 |
| `GET /exec?cmd=whoami` | 命令注入（受控 RCE 验证点） | 回显命令输出 |
| `GET /admin` + `X-Admin: 1` | Header 认证绕过 | 返回 admin 面板与 flag |
| `GET /` / `GET /version` | 指纹诱饵 | 伪造 PHP/nginx/Django/Struts 版本，供指纹识别练习 |

## WAF 模拟层

`--waf` 开启后，中间件按黑名单拦截明显 payload（`union select`、
`or 1=1`、`sleep(`、`cmd=`、`<script` 等），返回 403，并把每次拦截
（时间、请求、命中规则）记录到内存，`GET /waf-log` 可查看。

用途：验收「WAF 拦截策略变体」——直接攻击会被拦，编码/混淆/分块等
变体可尝试绕过，全程有逐次尝试与响应记录。

## 验收映射

- 阶段 3 退出条件「至少两类 Web 风险候选」：SQLi + XSS（+ 命令注入/认证绕过）
- 「一项受控验证」：`verify_sqli`（sqlmap）或 `execute_python` 对 `/exec` 做最小化验证
- 「一次 WAF 策略变体测试」：`--waf` 模式下用 `src/agents/shared/waf_bypass.py` 的变体生成器逐次尝试并记录响应
- 「Evidence 可回查」：扫描结果写黑板 + Evidence 后可用 `python -m src report --db ...` 追溯

## 注意

- 指纹诱饵（`X-Powered-By: PHP/7.4.3`、Struts 注释、`/version` 的 nginx/Django/MySQL）
  与实际技术栈（FastAPI + SQLite）不符，是刻意布置的诱饵，用于检验指纹识别与交叉验证能力。
- `/exec` 在真实靶机上等同命令执行，仅保留给本机受控验证；验收时只跑
  只读命令（如 `whoami`、`echo`）并记录副作用。
