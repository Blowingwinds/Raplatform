"""Web attack planner — reasoning rules for generic web vulnerabilities."""

_WEB_ATTACK_PATTERNS: list[dict] = [
    # Endpoint-based reasoning
    {"pattern": "login", "reasoning": "Login form → test SQL injection bypass, weak passwords, username enumeration",
     "actions": ["sqli", "auth-bypass"], "tool": "sqlmap"},
    {"pattern": "upload", "reasoning": "File upload → test file type bypass (extensions, MIME, magic bytes)",
     "actions": ["file-upload"], "tool": "nuclei"},
    {"pattern": "search", "reasoning": "Search box → test XSS reflection, SQLi in search",
     "actions": ["xss", "sqli"], "tool": "nuclei"},
    {"pattern": "api", "reasoning": "API endpoint → test SSRF, IDOR, JWT attacks, API-specific injection",
     "actions": ["ssrf", "sqli", "xss"], "tool": "nuclei"},
    {"pattern": "admin", "reasoning": "Admin panel → test auth bypass, default credentials, privilege escalation",
     "actions": ["auth-bypass", "default-login"], "tool": "nuclei"},
    {"pattern": "redirect", "reasoning": "Open redirect → test URL parameter injection for phishing",
     "actions": ["redirect"], "tool": "nuclei"},
    {"pattern": "reset", "reasoning": "Password reset → test token prediction, email injection",
     "actions": ["sqli", "auth-bypass"], "tool": "nuclei"},
    {"pattern": "register", "reasoning": "Registration → test XSS in user fields, duplicate registration bypass",
     "actions": ["xss", "sqli"], "tool": "nuclei"},
    {"pattern": "profile", "reasoning": "User profile → test IDOR, XSS in stored fields, CSRF",
     "actions": ["xss", "auth-bypass"], "tool": "nuclei"},
    {"pattern": "comment", "reasoning": "Comment form → test stored XSS, HTML injection, SQLi",
     "actions": ["xss", "sqli"], "tool": "nuclei"},
    {"pattern": "contact", "reasoning": "Contact form → test email injection, XSS, SSRF via mail server",
     "actions": ["xss", "ssrf"], "tool": "nuclei"},
    # Service-based reasoning
    {"service": "http", "reasoning": "Web service → full vulnerability scan",
     "actions": ["sqli", "xss", "ssrf", "ssti", "lfi", "redirect", "cors", "misconfig"], "tool": "nuclei"},
    {"service": "mysql", "reasoning": "MySQL port open → SQL injection on all web endpoints",
     "actions": ["sqli"], "tool": "sqlmap"},
    {"service": "postgresql", "reasoning": "PostgreSQL port open → SQL injection on all web endpoints",
     "actions": ["sqli"], "tool": "sqlmap"},
    {"service": "redis", "reasoning": "Redis exposed → test unauthorized access, SSRF via Redis",
     "actions": ["ssrf"], "tool": "python"},
]


async def plan(endpoints: list[dict], services: list[dict]) -> dict:
    """Given endpoints and services, produce a web attack plan."""
    steps: list[dict] = []

    # Endpoint-based
    for ep in endpoints:
        url = ep.get("url", "").lower()
        for pat in _WEB_ATTACK_PATTERNS:
            if "pattern" in pat and pat["pattern"] in url:
                steps.append({
                    "target": url,
                    "reasoning": pat["reasoning"],
                    "actions": pat["actions"],
                    "tool": pat["tool"],
                    "priority": "high",
                })

    # Service-based
    for svc in services:
        svc_name = svc.get("service_name", "").lower()
        for pat in _WEB_ATTACK_PATTERNS:
            if "service" in pat and pat.get("service") == svc_name:
                steps.append({
                    "target": svc.get("asset_ref", ""),
                    "reasoning": pat["reasoning"],
                    "actions": pat["actions"],
                    "tool": pat["tool"],
                    "priority": "high" if "sqli" in pat["actions"] else "medium",
                })

    return {
        "agent": "web_attack",
        "plan": list({(s["target"], tuple(s["actions"])): s for s in steps}.values()),
    }