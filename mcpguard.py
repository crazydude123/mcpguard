#!/usr/bin/env python3
"""
mcpguard — static analyzer for MCP server / MCP-using codebases.

Scans for the 7 bug classes documented in 2026 disclosures against
modelcontextprotocol/* and downstream consumers:

  C1  Incomplete invisible-character filter for prompt-injection defense
       (variants of GitHub MCP filter bypass, AWS-IaC sanitizer bypass)
  C2  SSRF gate that doesn't resolve DNS — hostname-to-private-IP bypass
       (Gemini CLI web_fetch class)
  C3  OAuth state validation absent / gated behind optional method
       (MCP TS SDK class, Vercel @ai-sdk/mcp class)
  C4  Path traversal in file-API endpoints lacking root-resolution check
       (Cloudflare sandbox-container class)
  C5  Local-file read via AI-supplied path in file-upload tool with no
       allowlist (Notion MCP class)
  C6  Auth bypass via opaque-token verifier that accepts any non-empty
       string + env-credential fallback in HTTP transport
       (mcp-atlassian community class)
  C7  Credential-issuing operations classified as read-only, bypassing
       READ_OPERATIONS_ONLY safety mode (AWS aws-api-mcp-server class)

Usage:
    mcpguard scan <path>
    mcpguard scan <path> --json
    mcpguard --version

Exit code = number of distinct classes hit (0 = clean).

License: MIT.  Source: https://github.com/<your-account>/mcpguard
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

VERSION = "0.1.0"


@dataclass
class Finding:
    cls: str
    severity: str
    title: str
    file: str
    line: int | None
    excerpt: str
    detail: str


@dataclass
class CheckResult:
    cls: str
    findings: list[Finding] = field(default_factory=list)


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".rs"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv", ".next", ".turbo"}


def walk_sources(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in CODE_EXTS:
            continue
        # skip generated / vendored
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        # skip test files for some classes; we'll still scan them when
        # specifically useful (test files often reveal intent).
        yield p


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def excerpt_around(text: str, idx: int, width: int = 80) -> str:
    start = max(0, idx - width // 4)
    end = min(len(text), idx + width)
    snippet = text[start:end].replace("\n", " ")
    return snippet.strip()


# ----------------------------------------------------------------------
# C1 — incomplete invisible-character filter
# ----------------------------------------------------------------------

# Codepoints that real prompt-injection-smuggling research has used.
# Each entry is (codepoint, mnemonic). A filter that purports to defeat
# invisible-text smuggling must remove at least these.
SMUGGLING_CODEPOINTS = [
    (0x200B, "ZWSP"),
    (0x200C, "ZWNJ"),
    (0x200D, "ZWJ"),
    (0x200E, "LRM"),
    (0x200F, "RLM"),
    (0xFE00, "VARIATION-SELECTOR-1"),
    (0xFE0F, "VARIATION-SELECTOR-16"),
    (0xE0100, "VARIATION-SELECTOR-SUPPLEMENT"),
    (0x202A, "BIDI-LRE"),
    (0x202E, "BIDI-RLO"),
    (0x2066, "BIDI-LRI"),
    (0x2069, "BIDI-PDI"),
    (0x2060, "WORD-JOINER"),
    (0x034F, "COMBINING-GRAPHEME-JOINER"),
    (0x115F, "HANGUL-CHOSEONG-FILLER"),
    (0xFFA0, "HALFWIDTH-HANGUL-FILLER"),
    (0xFFF9, "INTERLINEAR-ANNOTATION-ANCHOR"),
    (0x180E, "MONGOLIAN-VOWEL-SEPARATOR"),
    (0xFEFF, "ZWNBSP/BOM"),
    (0x00AD, "SOFT-HYPHEN"),
    (0xE0001, "LANGUAGE-TAG"),
]

# Heuristic: a file likely IS a filter if it defines a function whose
# name suggests it, OR if it removes a small set of specific codepoints.
FILTER_SIGNATURE_RE = re.compile(
    r"(filter[_\s]*invisible|sanitize|filter[_\s]*unicode|stripInvisible|removeInvisible|"
    r"shouldRemoveRune|isInvisibleChar)",
    re.IGNORECASE,
)


_RANGE_RE = re.compile(
    r"0x([0-9A-Fa-f]{2,6})\s*(?:<=?|\.\.|,|to)\s*ord\([^)]*\)\s*<=?\s*0x([0-9A-Fa-f]{2,6})"
    r"|0x([0-9A-Fa-f]{2,6})\s*<=?\s*\w+\s*<=?\s*0x([0-9A-Fa-f]{2,6})"
    r"|0x([0-9A-Fa-f]{2,6})\s*\.\.=?\s*0x([0-9A-Fa-f]{2,6})",
)


def codepoint_present(text: str, cp: int) -> bool:
    # Matches the codepoint in any of the forms a sanitizer is likely
    # to declare it: Python int, hex, \u, \U, char literal.
    needles = [
        f"0x{cp:X}", f"0x{cp:x}",
        f"\\u{cp:04X}", f"\\u{cp:04x}",
        f"\\u{{{cp:X}}}", f"\\u{{{cp:x}}}",
        str(cp),
    ]
    if cp <= 0xFFFF:
        needles.append(f"\\u{cp:04X}")
    if cp > 0xFFFF:
        needles.append(f"\\U{cp:08X}")
    if any(n in text for n in needles):
        return True
    # Also accept if any declared range covers this codepoint.
    for m in _RANGE_RE.finditer(text):
        groups = [g for g in m.groups() if g]
        if len(groups) >= 2:
            try:
                lo = int(groups[0], 16)
                hi = int(groups[1], 16)
                if lo <= cp <= hi:
                    return True
            except ValueError:
                continue
    return False


def check_c1_invisible_filter(root: Path) -> CheckResult:
    res = CheckResult(cls="C1")
    for f in walk_sources(root):
        text = read(f)
        if not FILTER_SIGNATURE_RE.search(text):
            continue
        # Count how many smuggling codepoints are referenced. If the
        # filter mentions any, it's claiming to be a filter; check
        # completeness.
        hit = [(cp, name) for cp, name in SMUGGLING_CODEPOINTS if codepoint_present(text, cp)]
        if not hit:
            continue
        miss = [(cp, name) for cp, name in SMUGGLING_CODEPOINTS if not codepoint_present(text, cp)]
        if not miss:
            continue
        # Skip noisy hits in test files when the matched signature is
        # only the literal token "sanitize" without a real function.
        if "test" in f.name.lower() and "def sanitize" not in text and "function sanitize" not in text:
            continue
        sig_match = FILTER_SIGNATURE_RE.search(text)
        res.findings.append(Finding(
            cls="C1",
            severity="medium",
            title="Incomplete invisible-character filter",
            file=str(f),
            line=line_of(text, sig_match.start()) if sig_match else None,
            excerpt=excerpt_around(text, sig_match.start()) if sig_match else "",
            detail=(
                f"Filter recognises {len(hit)}/{len(SMUGGLING_CODEPOINTS)} known smuggling codepoints. "
                f"Missing: {', '.join(name for _, name in miss[:10])}"
                + (f" (+{len(miss) - 10} more)" if len(miss) > 10 else "")
                + ". Use Unicode category 'Cf' for full coverage."
            ),
        ))
    return res


# ----------------------------------------------------------------------
# C2 — SSRF gate without DNS resolution
# ----------------------------------------------------------------------

# Looks for code paths that fetch a URL where the only "is-private" check
# is run against the hostname string (not a resolved IP), AND the actual
# fetch reuses the hostname (so DNS rebinding is possible too).
C2_GATE_PATTERNS = [
    re.compile(r"\bis[_-]?(private|local|loopback|blocked)\s*\(", re.IGNORECASE),
    re.compile(r"\bipaddress\.ip_address\s*\(\s*hostname", re.IGNORECASE),
    re.compile(r"\bnet\.ParseIP\s*\(", ),
]
C2_FETCH_PATTERNS = [
    re.compile(r"\bhttpx\.AsyncClient", ),
    re.compile(r"\brequests\.get\s*\(", ),
    re.compile(r"\bfetch\s*\(\s*url", ),
    re.compile(r"\bhttp\.Get\s*\(", ),
]
C2_DNS_RESOLVE_PATTERNS = [
    re.compile(r"\b(dns|net)\.(lookup|LookupIPAddr|resolve|gethostbyname)", re.IGNORECASE),
    re.compile(r"\bsocket\.gethostbyname\b", ),
    re.compile(r"\bipaddr\.parse|ipaddress\.ip_address.*lookup", re.IGNORECASE),
]


def check_c2_ssrf_no_dns(root: Path) -> CheckResult:
    res = CheckResult(cls="C2")
    for f in walk_sources(root):
        text = read(f)
        has_gate = any(p.search(text) for p in C2_GATE_PATTERNS)
        has_fetch = any(p.search(text) for p in C2_FETCH_PATTERNS)
        if not (has_gate and has_fetch):
            continue
        has_dns_resolve = any(p.search(text) for p in C2_DNS_RESOLVE_PATTERNS)
        if has_dns_resolve:
            continue
        m = next((p.search(text) for p in C2_GATE_PATTERNS if p.search(text)), None)
        res.findings.append(Finding(
            cls="C2",
            severity="high",
            title="SSRF gate lacks DNS resolution",
            file=str(f),
            line=line_of(text, m.start()) if m else None,
            excerpt=excerpt_around(text, m.start()) if m else "",
            detail=(
                "File checks 'is private' against a hostname string and then performs an HTTP fetch, but "
                "no DNS resolution is performed before the gate. A hostname that resolves to a private IP "
                "via DNS (e.g. localtest.me → 127.0.0.1, or attacker-controlled DNS → 169.254.169.254) "
                "bypasses the gate. Pin the resolved IP through the fetch (custom Agent / connect.lookup)."
            ),
        ))
    return res


# ----------------------------------------------------------------------
# C3 — OAuth state validation absent / optional-method gated
# ----------------------------------------------------------------------

C3_AUTH_FILE_HINTS = [
    re.compile(r"OAuthClientProvider", ),
    re.compile(r"authorization_code", ),
    re.compile(r"authorizationCode", ),
    re.compile(r"saveTokens", ),
]
C3_STATE_VALIDATE_RE = re.compile(
    r"(timingSafeEqual|secrets\.compare_digest|consumeState|checkState"
    r"|expectedState\s*===?\s*\w+State"
    r"|expectedState\s*!==?\s*\w+State"
    r"|returnedState\s*===?\s*\w+"
    r"|returnedState\s*!==?\s*\w+)",
    re.IGNORECASE,
)
C3_OPTIONAL_STATE_RE = re.compile(r"\bstoredState\?\s*\(|\bsaveState\?\s*\(", )


def check_c3_oauth_state(root: Path) -> CheckResult:
    res = CheckResult(cls="C3")
    for f in walk_sources(root):
        text = read(f)
        if not any(p.search(text) for p in C3_AUTH_FILE_HINTS):
            continue
        # Looks like an OAuth client file. Does it validate state?
        has_validate = bool(C3_STATE_VALIDATE_RE.search(text))
        has_optional_state = bool(C3_OPTIONAL_STATE_RE.search(text))
        if not has_validate:
            m = next((p.search(text) for p in C3_AUTH_FILE_HINTS if p.search(text)), None)
            res.findings.append(Finding(
                cls="C3",
                severity="high",
                title="OAuth state validation not detected in auth file",
                file=str(f),
                line=line_of(text, m.start()) if m else None,
                excerpt=excerpt_around(text, m.start()) if m else "",
                detail=(
                    "Auth-flow file does not contain any recognisable state-comparison pattern "
                    "(timingSafeEqual / compare_digest / checkState / explicit ===/!== of state values). "
                    "RFC 6749 §10.12 requires state validation. Confirm with manual review; bug if absent."
                ),
            ))
        elif has_optional_state:
            m = C3_OPTIONAL_STATE_RE.search(text)
            res.findings.append(Finding(
                cls="C3",
                severity="high",
                title="OAuth state-storage methods are OPTIONAL on the provider interface",
                file=str(f),
                line=line_of(text, m.start()),
                excerpt=excerpt_around(text, m.start()),
                detail=(
                    "Provider interface marks state-related methods as optional (?). If a consumer "
                    "implements state() but not storedState(), validation silently skips. Verify "
                    "the auth() function throws when state is generated without a means to retrieve it. "
                    "See Vercel @ai-sdk/mcp pattern."
                ),
            ))
    return res


# ----------------------------------------------------------------------
# C4 — path traversal in file-API endpoints
# ----------------------------------------------------------------------

C4_FILE_OP_RE = re.compile(
    r"\b(fs\.readFile|fs\.writeFile|fs\.rm|fs\.unlink|os\.remove|"
    r"open\s*\(\s*[^,)]*(req|user|args|payload)|"
    r"path\.join\s*\([^)]*req|path\.join\s*\([^)]*body)",
    re.IGNORECASE,
)
C4_REALPATH_RE = re.compile(
    r"\b(fs\.realpath|os\.path\.realpath|filepath\.EvalSymlinks|Path\.resolve\(\)\.relative_to)",
    re.IGNORECASE,
)
C4_STARTSWITH_GUARD_RE = re.compile(
    r"\bstartsWith\s*\(\s*\w*(allow|root|base|workdir)", re.IGNORECASE
)


def check_c4_path_traversal(root: Path) -> CheckResult:
    res = CheckResult(cls="C4")
    for f in walk_sources(root):
        text = read(f)
        m = C4_FILE_OP_RE.search(text)
        if not m:
            continue
        has_realpath = bool(C4_REALPATH_RE.search(text))
        has_startswith = bool(C4_STARTSWITH_GUARD_RE.search(text))
        if has_realpath and has_startswith:
            continue
        # Skip if file is purely tests
        if "test" in f.name.lower():
            continue
        res.findings.append(Finding(
            cls="C4",
            severity="medium",
            title="File operation on user-controlled path without realpath+root check",
            file=str(f),
            line=line_of(text, m.start()),
            excerpt=excerpt_around(text, m.start()),
            detail=(
                "File operation derives path from request/user/args input and does not appear to combine "
                "both fs.realpath (symlink-safe) and a startsWith(allowedRoot) check. Confirm path is "
                "anchored to an allowed root and resolved against symlinks before the operation."
            ),
        ))
    return res


# ----------------------------------------------------------------------
# C5 — local file read via AI-supplied path in upload tool
# ----------------------------------------------------------------------

C5_UPLOAD_RE = re.compile(
    r"\b(createReadStream|open\s*\(\s*[^,)]*(filePath|file_path|filepath))"
    r"|\bfs\.readFile\s*\(\s*[^,)]*(filePath|file_path)",
    re.IGNORECASE,
)
C5_BINARY_FORMAT_RE = re.compile(
    r"(format\s*[:=]\s*['\"]binary['\"]|format\s*===?\s*['\"]binary['\"]|"
    r"absolute path|uri-reference)",
    re.IGNORECASE,
)


def check_c5_local_file_upload(root: Path) -> CheckResult:
    res = CheckResult(cls="C5")
    for f in walk_sources(root):
        text = read(f)
        m = C5_UPLOAD_RE.search(text)
        if not m:
            continue
        binary_hint = bool(C5_BINARY_FORMAT_RE.search(text))
        if not binary_hint:
            continue
        # Has any allowlist / root check?
        has_root_check = bool(C4_STARTSWITH_GUARD_RE.search(text)) or "allowedRoot" in text or "uploadRoot" in text
        if has_root_check:
            continue
        res.findings.append(Finding(
            cls="C5",
            severity="high",
            title="Local file read via AI-supplied path in upload tool",
            file=str(f),
            line=line_of(text, m.start()),
            excerpt=excerpt_around(text, m.start()),
            detail=(
                "Tool reads a file from a path it received as a tool argument (likely from an LLM) and "
                "uploads/forwards the bytes. No allowed-root check detected. AI agent can be induced to "
                "read /etc/shadow, ~/.ssh/id_rsa, .env, etc. and exfiltrate via the upload destination. "
                "See Notion-MCP-server class."
            ),
        ))
    return res


# ----------------------------------------------------------------------
# C6 — opaque-token verifier accepts any non-empty string
# ----------------------------------------------------------------------

C6_OPAQUE_VERIFIER_RE = re.compile(
    r"def\s+verify_token|async\s+verify_token|def\s+verifyAccessToken|"
    r"async\s+verifyAccessToken",
    re.IGNORECASE,
)
C6_WEAK_BODY_HINT_RE = re.compile(
    r"if\s+not\s+token\s*:\s*return\s+None"
    r"|opaque[\s\S]{0,80}return\s+AccessToken"
    r"|accept[\s\S]{0,40}non[\s\S]{0,5}empty",
    re.IGNORECASE,
)


def check_c6_opaque_token(root: Path) -> CheckResult:
    res = CheckResult(cls="C6")
    for f in walk_sources(root):
        text = read(f)
        m = C6_OPAQUE_VERIFIER_RE.search(text)
        if not m:
            continue
        if not C6_WEAK_BODY_HINT_RE.search(text):
            continue
        res.findings.append(Finding(
            cls="C6",
            severity="critical",
            title="Token verifier accepts any non-empty string",
            file=str(f),
            line=line_of(text, m.start()),
            excerpt=excerpt_around(text, m.start()),
            detail=(
                "Token verifier returns success (AccessToken / authenticated) for any non-empty input. "
                "Combined with server-side env credentials in the HTTP transport, this allows "
                "unauthenticated callers to use the operator's upstream identity. See mcp-atlassian class."
            ),
        ))
    return res


# ----------------------------------------------------------------------
# C7 — credential-issuing operations in READ_OPERATIONS_ONLY allowlist
# ----------------------------------------------------------------------

# Common AWS / cloud credential-issuing CLI operations that should NOT
# be classified as read-only by safety modes.
C7_CRED_OPS = [
    "get-login", "get-login-password",
    "get-token",
    "generate-db-auth-token",
    "get-authorization-token", "GetAuthorizationToken",
    "AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML",
    "GetSessionToken", "GetFederationToken",
    "CreateAccessKey",
    "GetCredentialsForIdentity", "GetOpenIdToken",
    "GetRoleCredentials",
]


def check_c7_readonly_creds(root: Path) -> CheckResult:
    res = CheckResult(cls="C7")
    for f in walk_sources(root):
        if f.suffix not in {".py", ".json", ".yaml", ".yml"}:
            continue
        text = read(f)
        if "readonly" not in text.lower() and "read_only" not in text.lower():
            continue
        # Look near the readonly definition for credential-issuing ops.
        for op in C7_CRED_OPS:
            if op not in text:
                continue
            idx = text.find(op)
            # crude proximity test: was 'readonly' mentioned within
            # the surrounding 500 chars?
            window = text[max(0, idx - 250): idx + 250].lower()
            if "readonly" not in window and "read_only" not in window:
                continue
            res.findings.append(Finding(
                cls="C7",
                severity="high",
                title=f"Credential-issuing op '{op}' inside a read-only allowlist",
                file=str(f),
                line=line_of(text, idx),
                excerpt=excerpt_around(text, idx),
                detail=(
                    f"'{op}' is structurally a credential-issuing operation. Classifying it as read-only "
                    "bypasses safety modes that consumers rely on (e.g. READ_OPERATIONS_ONLY). Move to an "
                    "explicit credential-issuing category that requires consent. See AWS aws-api-mcp-server "
                    "class."
                ),
            ))
            break
    return res


# ----------------------------------------------------------------------
# orchestrator
# ----------------------------------------------------------------------

CHECKS = [
    ("C1", check_c1_invisible_filter),
    ("C2", check_c2_ssrf_no_dns),
    ("C3", check_c3_oauth_state),
    ("C4", check_c4_path_traversal),
    ("C5", check_c5_local_file_upload),
    ("C6", check_c6_opaque_token),
    ("C7", check_c7_readonly_creds),
]


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def scan(root: Path) -> list[Finding]:
    all_findings: list[Finding] = []
    for cls, check in CHECKS:
        result = check(root)
        all_findings.extend(result.findings)
    all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.cls, x.file))
    return all_findings


def render_markdown(findings: list[Finding], root: Path) -> str:
    out = [f"# mcpguard scan: `{root}`\n"]
    if not findings:
        out.append("**No findings.** Clean against mcpguard v" + VERSION + " ruleset.")
        return "\n".join(out)
    out.append(f"**{len(findings)} finding(s)** across "
               f"{len({f.cls for f in findings})} class(es).\n")
    for f in findings:
        out.append(f"### [{f.severity.upper()}] {f.cls} — {f.title}")
        loc = f.file + (f":{f.line}" if f.line else "")
        out.append(f"`{loc}`\n")
        if f.excerpt:
            out.append(f"```\n{f.excerpt}\n```")
        out.append(f.detail + "\n")
    return "\n".join(out)


def render_json(findings: list[Finding]) -> str:
    return json.dumps([f.__dict__ for f in findings], indent=2)


def main() -> int:
    p = argparse.ArgumentParser(prog="mcpguard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="store_true")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan")
    s.add_argument("path", type=Path)
    s.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.version:
        print(f"mcpguard {VERSION}")
        return 0

    if args.cmd != "scan":
        p.print_help()
        return 1

    root = args.path.resolve()
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    findings = scan(root)

    if args.json:
        print(render_json(findings))
    else:
        print(render_markdown(findings, root))

    return min(len({f.cls for f in findings}), 7)


if __name__ == "__main__":
    sys.exit(main())
