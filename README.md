# mcpguard

Static analyzer for MCP-server codebases. Catches the 7 bug classes that have produced public CVEs and bug-bounty payouts against `modelcontextprotocol/*` and downstream consumers in 2026.

```
pip install mcpguard
mcpguard scan path/to/your/mcp-server
```

## What it catches

| Class | Pattern | Public example |
|---|---|---|
| **C1** | Incomplete invisible-character filter for prompt-injection defense | github/github-mcp-server `pkg/sanitize/sanitize.go`, awslabs/mcp `aws-iac-mcp-server/sanitizer.py` |
| **C2** | SSRF gate that doesn't resolve DNS — hostname → private IP bypass | google-gemini/gemini-cli `web_fetch` tool |
| **C3** | OAuth state validation absent or gated behind optional method | modelcontextprotocol/typescript-sdk `auth.ts`, vercel/ai `@ai-sdk/mcp` |
| **C4** | Path traversal in file-API endpoints — no `realpath` + `startsWith` check | cloudflare/mcp-server-cloudflare `sandbox-container` |
| **C5** | Local file read via AI-supplied path in upload tool with no allowlist | makenotion/notion-mcp-server `http-client.ts` |
| **C6** | Opaque-token verifier accepts any non-empty string + env-credential HTTP fallback | sooperset/mcp-atlassian |
| **C7** | Credential-issuing operations marked read-only in safety-mode allowlist | awslabs/mcp `aws-api-mcp-server` |

All 7 classes correspond to **filed bug bounty reports / CVEs disclosed in May 2026.** mcpguard runs the same checks I ran by hand to find them.

## Why

MCP servers are proliferating. Most ship without a security audit. The 7 classes above are not bugs in MCP-the-protocol — they're bugs in **how every fresh MCP-server author re-invents the same controls**. Catch them at PR time, not after a researcher files at H1.

## Output

```
$ mcpguard scan ~/my-mcp-server
# mcpguard scan: /home/me/my-mcp-server

**2 finding(s)** across 2 class(es).

### [HIGH] C2 — SSRF gate lacks DNS resolution
`my-mcp-server/src/tools/fetch.ts:42`
```
function isBlockedHost(urlStr) { const hostname = new URL(urlStr).hostname; if (host
```
File checks 'is private' against a hostname string and then performs an HTTP fetch,
but no DNS resolution is performed before the gate. Pin the resolved IP through the
fetch (custom Agent / connect.lookup).

### [MEDIUM] C1 — Incomplete invisible-character filter
`my-mcp-server/src/sanitize.ts:18`
...
```

JSON output: `--json`.

## License

MIT.

## Premium (paid)

The free open-source ruleset above. **mcpguard pro** adds:

- Daily-updated ruleset (track new disclosed classes as they emerge)
- GitHub Action integration with PR comments
- Pre-baked reports for HackerOne / GitHub Security Advisory submission
- Office-hour Slack for triage questions

→ https://polar.sh/crazydude123/mcpguard-pro *(coming soon)*

## Disclosed cases I've personally filed (May 2026)

- `github/github-mcp-server` invisible-char filter (Informative — not OSS-eligible)
- `cloudflare/mcp-server-cloudflare` sandbox path traversal (Duplicate)
- `makenotion/notion-mcp-server` local file exfil (Informative+Dup)
- `google-gemini/gemini-cli` SSRF DNS bypass (Pending)
- `awslabs/mcp` aws-api-mcp-server credential extraction (Pending)
- `sooperset/mcp-atlassian` auth bypass (Critical CVE pending)
- `modelcontextprotocol/typescript-sdk` OAuth state CSRF (Pending)
- `awslabs/mcp` aws-iac-mcp-server filter (Pending)
- `vercel/ai` @ai-sdk/mcp OAuth state CSRF (Pending)

mcpguard's ruleset is the materialised version of that audit work.

## Author

[@crazydude123](https://github.com/crazydude123) — security researcher specialising in MCP-server audits. Available for paid audits of proprietary MCP integrations.
