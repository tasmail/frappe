"""Minimal authentication telemetry; never attach request bodies or account identifiers."""

import ipaddress
import json
import time
import uuid

import frappe


def validate_login_route():
	"""Optional ingress contract: nginx cannot classify arbitrary form-body cmd=login.

	Keep legacy behavior by default. Rate-limited deployments must opt in so login
	cannot be moved to an unthrottled URL using a body or duplicate query argument.
	"""
	if not frappe.conf.get("security_login_canonical_routes"):
		return
	if frappe.request.method != "POST" or frappe.request.path not in ("/", "/login", "/api/method/login"):
		frappe.throw(frappe._("Use POST on a canonical login endpoint."), frappe.PermissionError)


def log_failed_login():
	"""Emit once from LoginManager.fail; trust forwarding only from configured socket peers.

	Ingress MUST overwrite X-Forwarded-For with exactly one canonical client address.
	Do not configure a proxy network unless direct backend access is restricted to it.
	"""
	try:
		request = frappe.request
		peer = ipaddress.ip_address(request.remote_addr)
		trusted = frappe.conf.get("security_log_trusted_proxies", [])
		ip = str(peer)
		if any(peer in ipaddress.ip_network(network, strict=True) for network in trusted):
			ip = request.headers.get("X-Forwarded-For", "")
		if "%" in ip:
			return
		ip = str(ipaddress.ip_address(ip))
		event = {
			"event": "frappe.login.failed",
			"version": 1,
			"id": str(uuid.uuid4()),
			"time": int(time.time()),
			"site": frappe.local.site,
			"ip": ip,
		}
		frappe.logger("security_login", allow_site=False, with_more_info=False).error(
			json.dumps(event, separators=(",", ":"), ensure_ascii=True)
		)
	except Exception:
		# Telemetry failure must not replace the authentication exception or leak request context.
		pass
