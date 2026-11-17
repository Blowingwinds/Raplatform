"""Component vulnerability planner — reasoning for plugins, packages, services."""

_COMPONENT_RULES: list[dict] = [
    # CMS Plugins
    {"product": "wordpress", "extra": "plugin",
     "reasoning": "WordPress plugin detected → check known plugin CVEs, update status",
     "actions": ["cve", "wordpress"], "priority": "critical"},
    {"product": "drupal", "extra": "module",
     "reasoning": "Drupal module → check module-specific CVEs",
     "actions": ["cve", "drupal"], "priority": "critical"},
    {"product": "joomla", "extra": "component",
     "reasoning": "Joomla component → check component CVEs",
     "actions": ["cve"], "priority": "high"},
    # JS ecosystem
    {"product": "jquery", "reasoning": "jQuery version → check XSS CVEs (e.g., CVE-2020-11023)",
     "actions": ["cve", "xss"], "priority": "medium"},
    {"product": "react", "reasoning": "React → check XSS in dangerouslySetInnerHTML, CVE scan",
     "actions": ["cve", "xss"], "priority": "low"},
    {"product": "vue", "reasoning": "Vue → check prototype pollution, template injection",
     "actions": ["cve", "xss"], "priority": "medium"},
    {"product": "angular", "reasoning": "Angular → check template injection (sandbox escape history)",
     "actions": ["cve", "xss"], "priority": "medium"},
    {"product": "bootstrap", "reasoning": "Bootstrap → check XSS in tooltip/popover (CVE-2019-8331)",
     "actions": ["cve", "xss"], "priority": "low"},
    # Infrastructure services
    {"product": "redis", "reasoning": "Redis → test unauthenticated access, INFO, CONFIG, write test",
     "actions": ["unauth"], "priority": "critical"},
    {"product": "mongodb", "reasoning": "MongoDB → test unauthenticated access, list databases",
     "actions": ["unauth"], "priority": "high"},
    {"product": "mysql", "reasoning": "MySQL → test default credentials, CVE check for version",
     "actions": ["cve", "default-login"], "priority": "high"},
    {"product": "postgresql", "reasoning": "PostgreSQL → test default creds, CVE check (RCE history)",
     "actions": ["cve", "default-login"], "priority": "high"},
    {"product": "elasticsearch", "reasoning": "Elasticsearch → test unauth access, CVE check",
     "actions": ["cve", "unauth"], "priority": "critical"},
    {"product": "memcached", "reasoning": "Memcached → test unauth access, data dump",
     "actions": ["unauth"], "priority": "high"},
    {"product": "rabbitmq", "reasoning": "RabbitMQ → test default creds (guest/guest), management API",
     "actions": ["cve", "default-login"], "priority": "medium"},
    # Package managers
    {"product": "npm", "reasoning": "npm ecosystem → check known vulnerable packages via CVE",
     "actions": ["cve"], "priority": "medium"},
    {"product": "composer", "reasoning": "Composer/PHP packages → check known CVEs",
     "actions": ["cve"], "priority": "medium"},
    {"product": "pip", "reasoning": "Python packages → check known CVEs in requirements",
     "actions": ["cve"], "priority": "medium"},
    # Authentication / credential checks
    {"product": "default", "extra": "login",
     "reasoning": "Service with login → test default credentials, weak passwords",
     "actions": ["default-login"], "priority": "high"},
]


async def plan(fingerprints: list[dict], services: list[dict]) -> dict:
    """Given component fingerprints and services, produce a component attack plan."""
    steps: list[dict] = []

    for fp in fingerprints:
        name = fp.get("name", "").lower()
        extracted = str(fp.get("extracted", "")).lower()
        host = fp.get("host", fp.get("matched_at", ""))
        combined = f"{name} {extracted}"

        for rule in _COMPONENT_RULES:
            product = rule["product"]
            extra = rule.get("extra", "")
            if product in combined and (not extra or extra in combined):
                steps.append({
                    "target": host,
                    "component": name,
                    "reasoning": rule["reasoning"],
                    "actions": rule["actions"],
                    "priority": rule["priority"],
                })

    for svc in services:
        svc_name = svc.get("service_name", "").lower()
        for rule in _COMPONENT_RULES:
            if rule["product"] == svc_name:
                steps.append({
                    "target": svc.get("asset_ref", ""),
                    "component": svc_name,
                    "reasoning": rule["reasoning"],
                    "actions": rule["actions"],
                    "priority": rule["priority"],
                })

    return {
        "agent": "component_vuln",
        "plan": steps,
    }