# Failed-login telemetry (version 15)

`LoginManager.fail` emits one ERROR `security_login` record before database writes. The existing production logger defaults to ERROR; this is intentionally not INFO/WARNING. Bench-only rotation avoids duplicate site copies. Logging never includes username, password, message, request URL, headers, cookies, form dictionary or traceback. JSON contains version, event, UUID, Unix timestamp, site and canonical IP only. Telemetry failure does not change authentication behavior. Other authentication mechanisms that do not call `LoginManager.fail` are outside this contract (including API keys and some two-factor failures).

Default identity is the actual WSGI socket peer, **not** `frappe.local.request_ip` (which trusts arbitrary forwarding in this release). Configure `security_log_trusted_proxies` as exact CIDRs in common site configuration only after ensuring: the backend listener is reachable solely from those ingress peers; each hop overwrites X-Forwarded-For with a single client IP; Cloudflare restoration trusts only published Cloudflare source networks; backend nginx trusts only the designated frontend, not the whole private subnet. Containers must similarly restrict application ingress and overwrite forwarding. A syntactically valid header alone is not authentication. A malformed or multiple forwarded IP is discarded; absent trust logs the peer, not the claimed visitor. Scoped IPv6 is rejected.

The infrastructure PR must enforce and verify those boundaries before consuming events for bans. Set `security_login_canonical_routes: true` for protected deployments: this opt-in permits username/password login only via POST on `/`, `/login`, or `/api/method/login`. It closes a native legacy behavior where form-body `cmd=login` authenticates on arbitrary unthrottled URLs; nginx cannot safely inspect that body during its pre-access phase. The default remains false for release compatibility. Noncanonical clients must migrate before opting in. This guard raises PermissionError before authentication and is not counted as a confirmed credential failure. Do not enable automated bans against a backend/proxy address produced by an incomplete rollout. Logging works without the new setting, but those peer-only records are unsuitable for client banning behind a proxy.

Run isolated contract tests without a database:

```
python -m unittest discover -s frappe/tests -p test_security_log_standalone.py
```

Full bench authentication integration tests still require the normal Frappe test environment; the isolated tests do not establish live ingress correctness. No migration, patch-list entry or database schema change is needed.
