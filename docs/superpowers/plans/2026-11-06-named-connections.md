# Named Tilda connections implementation plan

Goal: One MCP connection exposes named project credentials and uses an explicit connection ID on each invocation. The owner manages encrypted keys in /settings.

Architecture: persistent store (SQLite on an explicitly persistent disk; Neon PostgreSQL for Render Free, selected by the owner); AES-GCM credentials encrypted separately from OAuth sessions; password/CSRF protected server-rendered settings. MCP tools list_connections, list_tilda_tools and call_tilda_tool use no shared active project. Existing one-key grants stay supported.

Constraints: Node 24; no tokens in chat, logs, Git or browser responses; no automatic paid resource creation; refuse memory-only persistence; preserve Origin/CSRF checks and 10-character password floor.

1. Write persistence/credential secrecy tests; implement vault + persistent storage adapters and SQL setup. Verify duplicates, replacement, delete, restart and database failure.
2. Write settings/OAuth tests; implement settings login, secure sessions, CSRF, named CRUD, optional initial connection during OAuth; retain legacy encrypted grants.
3. Write MCP routing tests; implement protocol handshake, tool discovery and explicit connection invocation with per-call session isolation. Reject unknown/deleted project IDs; don't retry writes.
4. Run full suite, inspect rendered settings if browser runtime can be provisioned, document actual verification limits and storage setup. Publish source in the existing repository preserving remote head.
