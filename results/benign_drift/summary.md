# benign drift — 2026-09-05 — Darwin arm64, node v20.20.2

servers 9 · versions 211 · failed to start 39 · releases compared 164

| server | versions | compared | none | description-only | schema | added/removed | drift/release | drifts/month | refused tools (median/max) | stable ×3 |
|---|---|---|---|---|---|---|---|---|---|---|
| @modelcontextprotocol/server-everything | 23/28 | 22 | 15 | 0 | 1 | 6 | 0.318 | 0.33 | 0/11 | yes |
| @modelcontextprotocol/server-filesystem | 16/19 | 15 | 9 | 2 | 1 | 3 | 0.4 | 0.28 | 1.0/14 | yes |
| @modelcontextprotocol/server-memory | 14/14 | 13 | 11 | 0 | 2 | 0 | 0.154 | 0.09 | 9.0/9 | yes |
| @modelcontextprotocol/server-sequential-thinking | 9/9 | 8 | 5 | 1 | 2 | 0 | 0.375 | 0.14 | 1/1 | yes |
| @notionhq/notion-mcp-server | 21/21 | 20 | 9 | 1 | 7 | 3 | 0.55 | 0.7 | 6/22 | yes |
| @playwright/mcp | 30/30 | 29 | 19 | 0 | 6 | 4 | 0.345 | 1.11 | 2.0/22 | yes |
| @supabase/mcp-server-supabase | 0/30 | 0 | 0 | 0 | 0 | 0 | None | None | 0/0 | ? |
| @upstash/context7-mcp | 30/30 | 29 | 19 | 0 | 10 | 0 | 0.345 | 1.24 | 1.0/2 | yes |
| chrome-devtools-mcp | 29/30 | 28 | 13 | 4 | 8 | 3 | 0.536 | 2.19 | 2/29 | yes |

pooled: drift on 64/164 releases = 0.39; 0.51 drifts per server-month; refused tools per drifting release median 1.5 max 29
kinds pooled: {'none': 100, 'tools-added-or-removed': 19, 'schema': 37, 'description-only': 8}
schema-class releases that are purely additive with the description untouched (P-BD.3's candidate): 1/37
