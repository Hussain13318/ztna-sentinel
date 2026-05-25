from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class AnomalyResult:
	is_anomalous: bool
	reason: str
	recommended_action: str  # allow / challenge / block


class SessionAnomalyDetector:
	"""AI-style anomaly detection with LangChain + local rule-based fallback."""

	def __init__(self) -> None:
		self._langchain_ready = self._check_langchain_availability()

	def _check_langchain_availability(self) -> bool:
		try:
			from langchain_core.prompts import PromptTemplate  # noqa: F401
			from langchain_core.runnables import RunnableLambda  # noqa: F401
			return True
		except Exception:
			return False

	def _normalize_session(self, session_summary: dict[str, Any]) -> dict[str, Any]:
		traffic_flags = session_summary.get("traffic_flags") or {}
		if isinstance(traffic_flags, list):
			traffic_flags = {flag: True for flag in traffic_flags}

		return {
			"user": str(session_summary.get("user", "unknown")),
			"ip": str(session_summary.get("ip", "unknown")),
			"role": str(session_summary.get("role", "unknown")).lower(),
			"risk_score": float(session_summary.get("risk_score", 0)),
			"traffic_flags": traffic_flags,
			"accessed_apps": session_summary.get("accessed_apps", []),
			"login_time": str(session_summary.get("login_time", "unknown")),
			"login_location": str(session_summary.get("login_location", "unknown")),
		}

	def _base_rule_analysis(self, session: dict[str, Any]) -> AnomalyResult:
		risk_score = max(0.0, min(100.0, session["risk_score"]))
		flags = session["traffic_flags"] if isinstance(session["traffic_flags"], dict) else {}
		role = session["role"]
		accessed_apps = [str(a).lower() for a in session.get("accessed_apps", [])]
		login_location = session.get("login_location", "unknown").lower()

		reasons: list[str] = []
		anomaly_points = 0

		if risk_score >= 75:
			anomaly_points += 4
			reasons.append(f"High dynamic risk score ({risk_score:.1f}).")
		elif risk_score >= 50:
			anomaly_points += 2
			reasons.append(f"Elevated dynamic risk score ({risk_score:.1f}).")

		if flags.get("high_packet_rate"):
			anomaly_points += 2
			reasons.append("Traffic spike detected: packet rate exceeded threshold.")

		if flags.get("unusual_ports_detected"):
			anomaly_points += 2
			reasons.append("Connections to unusual destination ports observed.")

		if flags.get("large_data_transfer"):
			anomaly_points += 3
			reasons.append("Large data transfer detected in session.")

		if login_location in {"unknown", "new", "untrusted", "suspicious"}:
			anomaly_points += 1
			reasons.append("Login originated from unknown/untrusted location.")

		if role == "viewer" and "admin_panel" in accessed_apps:
			anomaly_points += 4
			reasons.append("Privilege mismatch: viewer role attempted admin panel access.")

		if role == "analyst" and "admin_panel" in accessed_apps:
			anomaly_points += 3
			reasons.append("Privilege mismatch: analyst role attempted admin panel access.")

		is_anomalous = anomaly_points >= 3
		if anomaly_points >= 7:
			action = "block"
		elif anomaly_points >= 3:
			action = "challenge"
		else:
			action = "allow"

		if not reasons:
			reasons.append("Session behavior appears normal under current policy rules.")

		return AnomalyResult(
			is_anomalous=is_anomalous,
			reason=" ".join(reasons),
			recommended_action=action,
		)

	def _analyze_with_langchain(self, session: dict[str, Any]) -> AnomalyResult:
		"""Use a local LangChain prompt + runnable pipeline (no external API)."""
		from langchain_core.prompts import PromptTemplate
		from langchain_core.runnables import RunnableLambda

		prompt = PromptTemplate.from_template(
			"""
			You are a zero-trust anomaly analysis assistant.
			Analyze this session summary and provide a concise security judgment.

			Session JSON:
			{session_json}

			Output format:
			is_anomalous: <true|false>
			reason: <short explanation>
			recommended_action: <allow|challenge|block>
			""".strip()
		)

		formatted_prompt = prompt.format(session_json=json.dumps(session, indent=2))

		# Local rule-based "LLM" runnable step to avoid any external model/API dependency.
		def local_reasoner(_: str) -> str:
			base = self._base_rule_analysis(session)
			return (
				f"is_anomalous: {str(base.is_anomalous).lower()}\n"
				f"reason: {base.reason}\n"
				f"recommended_action: {base.recommended_action}"
			)

		chain = RunnableLambda(local_reasoner)
		chain_output = chain.invoke(formatted_prompt)

		return self._parse_chain_output(chain_output, session)

	def _parse_chain_output(self, output_text: str, session: dict[str, Any]) -> AnomalyResult:
		"""Parse expected text output; fallback safely if parsing is imperfect."""
		parsed = {
			"is_anomalous": None,
			"reason": "",
			"recommended_action": "",
		}

		for line in str(output_text).splitlines():
			lower = line.lower().strip()
			if lower.startswith("is_anomalous:"):
				value = line.split(":", 1)[1].strip().lower()
				parsed["is_anomalous"] = value in {"true", "1", "yes"}
			elif lower.startswith("reason:"):
				parsed["reason"] = line.split(":", 1)[1].strip()
			elif lower.startswith("recommended_action:"):
				parsed["recommended_action"] = line.split(":", 1)[1].strip().lower()

		if parsed["recommended_action"] not in {"allow", "challenge", "block"}:
			fallback = self._base_rule_analysis(session)
			return fallback

		if parsed["is_anomalous"] is None:
			parsed["is_anomalous"] = parsed["recommended_action"] in {"challenge", "block"}

		if not parsed["reason"]:
			parsed["reason"] = "Anomaly decision generated by local LangChain policy analyzer."

		return AnomalyResult(
			is_anomalous=bool(parsed["is_anomalous"]),
			reason=parsed["reason"],
			recommended_action=parsed["recommended_action"],
		)

	def analyze_session(self, session_summary: dict[str, Any]) -> dict[str, Any]:
		"""Main API: detect anomaly and return required decision fields."""
		session = self._normalize_session(session_summary)

		try:
			if self._langchain_ready:
				result = self._analyze_with_langchain(session)
			else:
				result = self._base_rule_analysis(session)
		except Exception:
			# Guaranteed fallback path if any LangChain/runtime issue occurs.
			result = self._base_rule_analysis(session)

		return {
			"is_anomalous": result.is_anomalous,
			"reason": result.reason,
			"recommended_action": result.recommended_action,
		}


if __name__ == "__main__":
	detector = SessionAnomalyDetector()
	sample_summary = {
		"user": "alice",
		"ip": "203.0.113.10",
		"role": "viewer",
		"risk_score": 78,
		"traffic_flags": {
			"high_packet_rate": True,
			"unusual_ports_detected": True,
			"large_data_transfer": False,
		},
		"accessed_apps": ["app1", "admin_panel"],
		"login_time": "23:42",
		"login_location": "unknown",
	}

	print(detector.analyze_session(sample_summary))
