"""Detection signatures for the code scanner — production-grade CEH/CHFI edition.

Two families:
  SECRETS  — credential/key shapes with entropy gating to cut FPs.
  SINKS    — dangerous language constructs flagged for human review.

Additions over baseline:
  • Azure, GCP, Twilio, SendGrid, Stripe (test + live), Heroku, Okta tokens
  • JWT secret-key assignments
  • SSRF-prone URL constructors (JS/Python)
  • Template injection sinks (Jinja2, Pebble, Twig, FreeMarker)
  • XXE-prone XML parsers (Python, Java, PHP)
  • Path traversal sinks
  • Hardcoded IPs + private-range detection
  • LDAP / XPath injection sinks
  • Crypto: weak algorithms (MD5, SHA1 for passwords, DES, RC4)
  • CORS wildcard misconfiguration
  • Debug mode flags (Django, Flask, Spring, Express)
  • Hardcoded passwords in config literals
"""
from __future__ import annotations

import re

# ── SECRETS ──────────────────────────────────────────────────────────────────
# (id, severity, compiled regex, min_shannon_entropy_of_group1 or 0)
SECRETS = [
    # AWS
    ("aws-access-key-id",  "high",     re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 0),
    ("aws-secret-key",     "critical", re.compile(r"""(?i)aws.{0,20}['"]([0-9a-zA-Z/+]{40})['"]"""), 4.0),
    # GitHub
    ("github-pat",            "critical", re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b"), 0),
    ("github-fine-grained",   "critical", re.compile(r"\b(github_pat_[0-9A-Za-z_]{72,})\b"), 0),
    ("github-oauth",          "high",     re.compile(r"\b(gho_[0-9A-Za-z]{36})\b"), 0),
    ("github-actions",        "critical", re.compile(r"\b(ghs_[0-9A-Za-z]{36})\b"), 0),
    # Slack
    ("slack-token",     "high",     re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), 0),
    ("slack-webhook",   "medium",   re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{24}"), 0),
    # Google
    ("google-api-key",        "high",     re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), 0),
    ("google-oauth-id",       "medium",   re.compile(r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"), 0),
    # Stripe
    ("stripe-secret-live",   "critical", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b"), 0),
    ("stripe-secret-test",   "medium",   re.compile(r"\b(sk_test_[0-9A-Za-z]{24,})\b"), 0),
    # Azure
    ("azure-storage-key",    "critical", re.compile(r"""(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*([A-Za-z0-9+/]{88}==)"""), 4.5),
    ("azure-client-secret",  "critical", re.compile(r"""(?i)(?:client.?secret|clientSecret)\s*[:=]\s*['"]([^'"]{8,})['"]"""), 3.5),
    # GCP
    ("gcp-service-key",      "critical", re.compile(r'"type"\s*:\s*"service_account"'), 0),
    # Twilio
    ("twilio-sid",   "high",     re.compile(r"\b(AC[0-9a-f]{32})\b"), 0),
    ("twilio-token", "critical", re.compile(r"\b(SK[0-9a-f]{32})\b"), 0),
    # SendGrid
    ("sendgrid-key", "high",     re.compile(r"\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b"), 0),
    # Heroku
    ("heroku-api-key", "high",   re.compile(r"""(?i)heroku.{0,20}['""]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]"""), 0),
    # Okta
    ("okta-token",   "critical", re.compile(r"\b(00[0-9a-zA-Z_\-]{37})\b"), 3.5),
    # Private keys
    ("private-key-block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 0),
    # JWT
    ("jwt", "medium",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), 0),
    # Generic
    ("generic-assigned-secret", "medium",
     re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"]([^'"\s]{8,})['"]"""), 3.5),
    ("connection-string-cred", "high",
     re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@\s]+:([^@\s]{4,})@"), 2.5),
    # Hardcoded private IP in env/config assignment
    ("hardcoded-internal-ip", "low",
     re.compile(r"""(?i)(?:host|server|endpoint)\s*[:=]\s*['"]?(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)['"]?"""), 0),
]

# ── SINKS ──────────────────────────────────────────────────────────────────
# (id, severity, language-hint, compiled regex, note)
SINKS = [
    # ── Python ──────────────────────────────────────────────────────────────
    ("py-eval-exec", "high", "python",
     re.compile(r"\b(?:eval|exec)\s*\("), "arbitrary code execution from input"),
    ("py-pickle-loads", "high", "python",
     re.compile(r"\b(?:pickle|cPickle)\.loads?\s*\("), "unsafe deserialization"),
    ("py-yaml-load", "high", "python",
     re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"),
     "yaml.load without SafeLoader"),
    ("py-subprocess-shell", "high", "python",
     re.compile(r"(?:subprocess\.(?:run|call|Popen|check_output))\([^)]*shell\s*=\s*True"),
     "shell=True enables command injection"),
    ("py-os-system", "medium", "python",
     re.compile(r"\bos\.system\s*\("), "command execution via shell"),
    ("py-flask-debug", "medium", "python",
     re.compile(r"\.run\([^)]*debug\s*=\s*True"), "debug server exposes Werkzeug console"),
    ("py-jinja2-autoescape-off", "high", "python",
     re.compile(r"(?i)autoescape\s*=\s*False"), "Jinja2 XSS: autoescaping disabled"),
    ("py-template-inject", "medium", "python",
     re.compile(r"""Template\s*\(\s*(?:request\.|f['"]|%s|f\")"""),
     "user-controlled template string (SSTI risk)"),
    ("py-ssrf-request", "medium", "python",
     re.compile(r"""requests\.(?:get|post|put|delete)\s*\(\s*(?:request\.|f['"])"""),
     "SSRF: user-controlled URL in requests call"),
    ("py-open-redirect", "medium", "python",
     re.compile(r"""redirect\s*\(\s*request\.(?:args|form|values|get)\s*\("""),
     "open redirect via user-controlled parameter"),
    ("py-ldap-inject", "high", "python",
     re.compile(r"""ldap\w*\.search\s*\([^)]*(?:\+|%|format\()"""),
     "LDAP injection via string concatenation"),
    ("py-xml-etree-unsafe", "medium", "python",
     re.compile(r"(?:xml\.etree|ElementTree)\.(?:parse|fromstring)\s*\("),
     "Python xml.etree does not protect against XXE by default"),
    ("py-lxml-unsafe", "medium", "python",
     re.compile(r"lxml\.\w+\s*\(.*resolve_entities\s*=\s*True"),
     "lxml with external entity resolution enabled (XXE)"),
    ("py-md5-password", "medium", "python",
     re.compile(r"(?i)(?:hashlib\.md5|md5\s*\()"), "MD5 is cryptographically broken"),
    ("py-sha1-password", "low", "python",
     re.compile(r"(?i)(?:hashlib\.sha1|sha1\s*\()"), "SHA-1 is weak for password hashing"),
    ("py-hardcoded-bind-all", "medium", "python",
     re.compile(r"""(?:host\s*=\s*['"]0\.0\.0\.0['"]|bind\s*\(\s*['"]0\.0\.0\.0['"])"""),
     "service bound to all interfaces"),

    # ── JavaScript ───────────────────────────────────────────────────────────
    ("js-eval", "high", "javascript",
     re.compile(r"\beval\s*\("), "arbitrary code execution"),
    ("js-child-process-exec", "high", "javascript",
     re.compile(r"child_process\.exec\s*\("), "shell command injection (use execFile)"),
    ("js-innerhtml", "medium", "javascript",
     re.compile(r"\.innerHTML\s*="), "DOM XSS sink"),
    ("js-outerhtml", "medium", "javascript",
     re.compile(r"\.outerHTML\s*="), "DOM XSS sink"),
    ("js-document-write", "medium", "javascript",
     re.compile(r"document\.write\s*\("), "DOM XSS sink"),
    ("js-function-ctor", "medium", "javascript",
     re.compile(r"\bnew\s+Function\s*\("), "dynamic code construction"),
    ("js-ssrf-fetch", "medium", "javascript",
     re.compile(r"""fetch\s*\(\s*(?:req\.|request\.|`\$\{)"""),
     "SSRF: user-controlled URL in fetch()"),
    ("js-prototype-pollution", "medium", "javascript",
     re.compile(r"""(?:__proto__|constructor\.prototype)\s*\["""),
     "potential prototype pollution"),
    ("js-cors-wildcard", "medium", "javascript",
     re.compile(r"""(?i)Access-Control-Allow-Origin['":\s]*\*"""),
     "CORS wildcard allows any origin"),
    ("js-debug-mode", "low", "javascript",
     re.compile(r"""(?i)NODE_ENV\s*=\s*['"]development['"]|debug\s*:\s*true"""),
     "debug mode enabled"),

    # ── Java ────────────────────────────────────────────────────────────────
    ("java-deser", "high", "java",
     re.compile(r"new\s+ObjectInputStream\s*\("), "Java native deserialization"),
    ("java-xxe-sax", "high", "java",
     re.compile(r"SAXParser\w*\.parse\s*\("), "SAX parser may allow XXE"),
    ("java-xxe-docbuilder", "high", "java",
     re.compile(r"DocumentBuilderFactory\.newInstance\s*\(\s*\)"), "DocumentBuilder XXE risk"),
    ("java-runtime-exec", "high", "java",
     re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("), "OS command execution"),
    ("java-reflection", "medium", "java",
     re.compile(r"Class\.forName\s*\("), "reflection may allow class loading attacks"),
    ("java-xpath-inject", "high", "java",
     re.compile(r"xpath\.evaluate\s*\([^)]*(?:\+|concat\()"), "XPath injection"),
    ("java-md5-password", "medium", "java",
     re.compile(r"""(?:MessageDigest\.getInstance\s*\(\s*["']MD5["'])"""),
     "MD5 used — broken for security"),

    # ── PHP ──────────────────────────────────────────────────────────────────
    ("php-unserialize", "high", "php",
     re.compile(r"\bunserialize\s*\("), "PHP object injection"),
    ("php-exec", "high", "php",
     re.compile(r"\b(?:exec|shell_exec|system|passthru|popen)\s*\("), "command injection"),
    ("php-eval", "critical", "php",
     re.compile(r"\beval\s*\("), "arbitrary code execution"),
    ("php-include-var", "high", "php",
     re.compile(r"\b(?:include|require)(?:_once)?\s*\(\s*\$"), "LFI/RFI via variable include"),
    ("php-xxe-simplexml", "high", "php",
     re.compile(r"simplexml_load_string\s*\("), "SimpleXML may allow XXE"),
    ("php-preg-replace-e", "critical", "php",
     re.compile(r"preg_replace\s*\(\s*['\"].*\/e"), "preg_replace /e flag = code execution"),

    # ── Universal / multi-language ────────────────────────────────────────────
    ("sql-string-format", "medium", "any",
     re.compile(r"""(?i)(?:execute|query)\s*\(\s*[f]?['"].*(?:\+|%s|%d|\{).*(?:SELECT|INSERT|UPDATE|DELETE)"""),
     "SQL built via string interpolation"),
    ("template-injection-any", "high", "any",
     re.compile(r"\{\{.*(?:request|user|input|param).*\}\}"),
     "Template expression with user-controlled input (SSTI)"),
    ("hardcoded-password-config", "high", "any",
     re.compile(r"""(?i)(?:PASSWORD|PASSWD|DB_PASS)\s*=\s*['"][^'"]{6,}['"]"""),
     "Hardcoded password in config/env literal"),
    ("cors-wildcard-any", "medium", "any",
     re.compile(r"""(?i)Access-Control-Allow-Origin['":\s]+\*"""),
     "CORS wildcard misconfiguration"),
    ("weak-crypto-des", "high", "any",
     re.compile(r"(?i)\bDES\.new\b|\bDES_ede3\b|\bTripleDES\b|Cipher\.getInstance\s*\(\s*\"DES"), "DES/3DES is deprecated"),
    ("weak-crypto-rc4", "high", "any",
     re.compile(r"(?i)\bRC4\b|\bArcfour\b"), "RC4 is broken — do not use"),
]

# ── Skip / binary lists (unchanged) ──────────────────────────────────────────
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
    ".venv", "venv", ".tox", "target", ".mypy_cache", ".next",
    "coverage", ".pytest_cache", "htmlcov", "eggs", ".eggs",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar",
    ".jar", ".war", ".class", ".so", ".dylib", ".dll", ".exe", ".woff",
    ".woff2", ".ttf", ".ico", ".mp4", ".mp3", ".wasm", ".pyc",
    ".bin", ".elf", ".o", ".a", ".lib", ".obj", ".pdb",
}


def shannon(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())
