"""Database-independent contract tests: python -m unittest discover -s frappe/tests -p test_security_log_standalone.py."""

import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import Mock, patch


class SecurityLogTest(unittest.TestCase):
	def setUp(self):
		self.frappe = types.SimpleNamespace(
			conf={"security_log_trusted_proxies": ["10.0.0.2/32"]},
			local=types.SimpleNamespace(site="example.test"),
			request=types.SimpleNamespace(remote_addr="10.0.0.2", headers={"X-Forwarded-For": "2001:db8::1"}),
			logger=Mock(),
		)
		spec = importlib.util.spec_from_file_location(
			"security_log", pathlib.Path(__file__).parents[1] / "utils" / "security_log.py"
		)
		self.module = importlib.util.module_from_spec(spec)
		with patch.dict(sys.modules, {"frappe": self.frappe}):
			spec.loader.exec_module(self.module)

	def test_fail_hook_precedes_database_work(self):
		import ast

		tree = ast.parse((pathlib.Path(__file__).parents[1] / "auth.py").read_text())
		manager = next(
			node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LoginManager"
		)
		fail = next(
			node for node in manager.body if isinstance(node, ast.FunctionDef) and node.name == "fail"
		)
		module = ast.Module(body=[fail], type_ignores=[])
		log = Mock()
		self.frappe.AuthenticationError = type("AuthenticationError", (Exception,), {})
		self.frappe.local.response = {}
		self.frappe.db = Mock()
		namespace = {"frappe": self.frappe, "add_authentication_log": Mock(), "_": lambda s: s}
		exec(compile(module, "auth.py", "exec"), namespace)
		with patch.dict(
			sys.modules, {"frappe.utils.security_log": types.SimpleNamespace(log_failed_login=log)}
		):
			with self.assertRaises(self.frappe.AuthenticationError):
				namespace["fail"](None, "Incorrect password", "user")
		log.assert_called_once_with()
		self.frappe.db.commit.assert_called_once_with()

	def test_error_event_survives_production_error_threshold(self):
		import io
		import logging

		output = io.StringIO()
		logger = logging.Logger("isolated-security", level=logging.ERROR)
		logger.addHandler(logging.StreamHandler(output))
		self.frappe.logger.return_value = logger
		self.module.log_failed_login()
		self.assertEqual(json.loads(output.getvalue())["event"], "frappe.login.failed")

	def test_opt_in_canonical_routes_close_body_encoded_login_bypass(self):
		self.frappe.conf["security_login_canonical_routes"] = True
		self.frappe.PermissionError = PermissionError
		self.frappe._ = lambda s: s
		self.frappe.throw = Mock(side_effect=PermissionError)
		for path, method in (("/unlimited", "POST"), ("/api/method/login", "GET")):
			self.frappe.request.path = path
			self.frappe.request.method = method
			with self.assertRaises(PermissionError):
				self.module.validate_login_route()
		for path in ("/", "/login", "/api/method/login"):
			self.frappe.request.path = path
			self.frappe.request.method = "POST"
			self.module.validate_login_route()
		self.frappe.conf = {}
		self.frappe.request.path = "/legacy"
		self.module.validate_login_route()

	def test_safe_event_at_error_level(self):
		self.module.log_failed_login()
		self.frappe.logger.assert_called_once_with("security_login", allow_site=False, with_more_info=False)
		event = json.loads(self.frappe.logger.return_value.error.call_args.args[0])
		self.assertEqual(event["ip"], "2001:db8::1")
		self.assertEqual(event["event"], "frappe.login.failed")
		self.assertEqual(set(event), {"event", "version", "id", "time", "site", "ip"})

	def test_untrusted_peer_never_uses_forwarded_header(self):
		self.frappe.request.remote_addr = "192.0.2.1"
		self.module.log_failed_login()
		event = json.loads(self.frappe.logger.return_value.error.call_args.args[0])
		self.assertEqual(event["ip"], "192.0.2.1")

	def test_invalid_or_multivalue_forwarding_not_logged(self):
		for value in ("1.2.3.4, 5.6.7.8", "1.2.3.4\nforged", "invalid", "fe80::1%eth0"):
			self.frappe.request.headers["X-Forwarded-For"] = value
			self.module.log_failed_login()
		self.frappe.logger.assert_not_called()

	def test_logging_failure_does_not_change_authentication(self):
		self.frappe.logger.side_effect = OSError("disk full")
		self.module.log_failed_login()

	def test_absent_trust_defaults_to_peer(self):
		self.frappe.conf = {}
		self.module.log_failed_login()
		event = json.loads(self.frappe.logger.return_value.error.call_args.args[0])
		self.assertEqual(event["ip"], "10.0.0.2")
