"""Framework vulnerability planner — reasoning rules for framework/runtime CVEs."""

_FRAMEWORK_RULES: list[dict] = [
    # Java ecosystem
    {"product": "spring", "actions": ["CVE check (Spring4Shell, Spring Cloud RCE)",
                                        "actuator exposure", "Spring Boot admin"],
     "tags": ["cve", "spring", "exposures"]},
    {"product": "tomcat", "actions": ["manager default creds", "CVE check (Ghostcat, etc)",
                                       "examples directory", "version enumeration"],
     "tags": ["cve", "tomcat", "default-login"]},
    {"product": "struts", "actions": ["S2-xxx CVEs", "OGNL injection", "devMode check"],
     "tags": ["cve", "struts"]},
    {"product": "weblogic", "actions": ["T3 protocol", "console default creds", "CVE scan"],
     "tags": ["cve", "default-login"]},
    {"product": "jboss", "actions": ["JMX console", "admin console default creds",
                                      "CVE (deserialization)"],
     "tags": ["cve", "default-login", "misconfig"]},
    # Python ecosystem
    {"product": "django", "actions": ["debug mode", "SQL injection in ORM", "admin panel",
                                       "CVE scan", "SECRET_KEY exposure"],
     "tags": ["cve", "sqli", "misconfig", "exposures"]},
    {"product": "flask", "actions": ["debug console (Werkzeug)", "SSTI (Jinja2)",
                                      "SECRET_KEY exposure", "CVE scan"],
     "tags": ["cve", "ssti", "misconfig", "exposures"]},
    # PHP ecosystem
    {"product": "laravel", "actions": ["debug mode (.env)", "APP_KEY check", "CVE scan",
                                        "Ignition RCE", "debug routes"],
     "tags": ["cve", "misconfig", "exposures"]},
    {"product": "symfony", "actions": ["profiler exposure", "debug mode", "CVE scan"],
     "tags": ["cve", "misconfig", "exposures"]},
    {"product": "wordpress", "actions": ["xmlrpc.php", "user enumeration", "REST API exposure",
                                          "CVE (core)"],  # plugins → component_vuln
     "tags": ["cve", "wordpress", "misconfig"]},
    # JS ecosystem
    {"product": "express", "actions": ["debug endpoints", "CVE scan", "helmet check"],
     "tags": ["cve", "misconfig"]},
    {"product": "next.js", "actions": ["SSR prototype pollution", "middleware bypass",
                                        "CVE scan"],
     "tags": ["cve", "misconfig"]},
    # Ruby
    {"product": "rails", "actions": ["CVE scan", "secret_key_base exposure",
                                      "mass assignment", "debug routes"],
     "tags": ["cve", "misconfig", "exposures"]},
    # Web servers
    {"product": "apache", "actions": ["CVE-2021-41773 path traversal", "CVE-2021-42013",
                                       "server-status exposure", ".htaccess bypass"],
     "tags": ["cve", "lfi", "misconfig"]},
    {"product": "nginx", "actions": ["alias traversal", "CRLF injection",
                                      "path traversal via misconfig"],
     "tags": ["cve", "lfi", "misconfig"]},
    {"product": "iis", "actions": ["short-name (tilde) enumeration", "web.config exposure",
                                    "CVE (HTTP.sys, etc)", "default install check"],
     "tags": ["cve", "misconfig", "exposures"]},
    # Language runtimes
    {"product": "php", "actions": ["CVE-2024-4577 PHP-CGI RCE", "phpinfo exposure",
                                    "disable_functions bypass candidates"],
     "tags": ["cve", "misconfig"]},
    {"product": "java", "actions": ["deserialization endpoints", "JMX/RMI exposure",
                                     "actuator/health"],
     "tags": ["cve", "misconfig"]},
    {"product": "python", "actions": ["Werkzeug debug console", "Pickle deserialization"],
     "tags": ["cve", "misconfig"]},
]


async def plan(fingerprints: list[dict]) -> dict:
    """Given framework fingerprints, produce a prioritized attack plan."""
    steps: list[dict] = []
    seen: set[str] = set()

    for fp in fingerprints:
        name = fp.get("name", "").lower()
        extracted = str(fp.get("extracted", "")).lower()
        host = fp.get("host", fp.get("matched_at", ""))
        combined = f"{name} {extracted}"

        for rule in _FRAMEWORK_RULES:
            product = rule["product"]
            if product in combined and product not in seen:
                seen.add(product)
                steps.append({
                    "target": host,
                    "detected": name,
                    "version": extracted,
                    "actions": rule["actions"],
                    "nuclei_tags": rule["tags"],
                    "priority": "critical" if "cve" in rule["tags"] else "high",
                })

    return {
        "agent": "framework_vuln",
        "fingerprints_matched": list(seen),
        "plan": steps,
    }