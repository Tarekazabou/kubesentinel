import json
import logging
import os
import threading
import time
from datetime import datetime

from db import get_db


class TriageWorker:
    def __init__(
        self,
        poll_interval: int = 30,
        batch_size: int = 10,
        gemini_model=None,
        can_call_gemini=None,
        write_forensics_fn=None,
    ):
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        self._stop_event = threading.Event()
        self._thread = None
        self._logger = logging.getLogger(__name__)

        self.enrich_with_gemini = os.getenv("ENRICH_WITH_GEMINI", "false").lower() not in ("false", "0")

        self.gemini_model = gemini_model
        self.can_call_gemini = can_call_gemini
        self.write_forensics_fn = write_forensics_fn

        # Fallback wiring for standalone use. In normal flow server.py injects these
        # references so the worker shares the same Gemini model and limiter state.
        if self.gemini_model is None or self.can_call_gemini is None or self.write_forensics_fn is None:
            from server import can_call_gemini as server_can_call_gemini
            from server import gemini_model as server_gemini_model
            from server import write_incident_to_forensics

            if self.gemini_model is None:
                self.gemini_model = server_gemini_model
            if self.can_call_gemini is None:
                self.can_call_gemini = server_can_call_gemini
            if self.write_forensics_fn is None:
                self.write_forensics_fn = write_incident_to_forensics

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="triage-worker")
        self._thread.start()
        self._logger.info(
            "Triage worker started (poll_interval=%ss, batch_size=%s)",
            self.poll_interval,
            self.batch_size,
        )

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._process_batch()
            except Exception as exc:
                self._logger.error("Triage batch loop error: %s", exc)
            self._stop_event.wait(self.poll_interval)

    def _process_batch(self):
        conn = get_db()
        rows = conn.execute(
            """
            SELECT *
            FROM incident_staging
            WHERE status = 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT ?
            """,
            (self.batch_size,),
        ).fetchall()

        for row in rows:
            self._triage_one(row)

    def _triage_one(self, row):
        if not self.enrich_with_gemini:
            passthrough_result = {
                "verdict": "confirmed",
                "reason": "Gemini triage disabled; auto-confirmed in passthrough mode.",
                "severity": None,
                "mitre_tactic": None,
                "enriched_description": None,
                "remediation": None,
                "triage_source": "passthrough",
            }
            self._write_confirmed_to_forensics(row, passthrough_result)
            conn = get_db()
            self._update_staging_row(conn, row["id"], "confirmed", passthrough_result)
            return

        try:
            if self.gemini_model is None:
                raise RuntimeError("Gemini model is not initialized")

            if not self.can_call_gemini():
                self._logger.info("Gemini triage rate limit reached. Deferring row id=%s", row["id"])
                return

            incident_data = json.loads(row["raw_event"])
            prompt = self._build_triage_prompt(incident_data, float(row["if_score"]))
            response = self.gemini_model.generate_content(prompt)

            triage_result = self._parse_triage_json(getattr(response, "text", ""))
            triage_result["triage_source"] = "llm"

            verdict = (triage_result.get("verdict") or "").strip().lower()
            if verdict not in ("confirmed", "rejected"):
                raise ValueError(f"Unexpected verdict value: {verdict}")

            conn = get_db()
            if verdict == "confirmed":
                self._write_confirmed_to_forensics(row, triage_result)
                self._update_staging_row(conn, row["id"], "confirmed", triage_result)
            else:
                self._update_staging_row(conn, row["id"], "rejected", triage_result)

        except Exception as exc:
            # Keep as pending so the next poll retries.
            self._logger.error("Triage failed for row id=%s (left pending): %s", row["id"], exc)

    def _write_confirmed_to_forensics(self, row, triage_result):
        incident_data = json.loads(row["raw_event"])
        metadata = incident_data.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            incident_data["metadata"] = metadata

        metadata["triage_severity"] = triage_result.get("severity")
        metadata["mitre_tactic"] = triage_result.get("mitre_tactic")
        metadata["triage_description"] = triage_result.get("enriched_description")
        metadata["remediation"] = triage_result.get("remediation")
        metadata["triage_source"] = triage_result.get("triage_source", "llm")

        if triage_result.get("enriched_description"):
            incident_data["description"] = triage_result["enriched_description"]

        self.write_forensics_fn(incident_data)

    def _update_staging_row(self, conn, row_id, verdict, triage_result):
        conn.execute(
            """
            UPDATE incident_staging
            SET status = ?,
                triage_reason = ?,
                severity = ?,
                mitre_tactic = ?,
                enriched_description = ?,
                remediation = ?,
                triaged_at = ?
            WHERE id = ?
            """,
            (
                verdict,
                triage_result.get("reason"),
                triage_result.get("severity"),
                triage_result.get("mitre_tactic"),
                triage_result.get("enriched_description"),
                triage_result.get("remediation"),
                datetime.utcnow().isoformat() + "Z",
                row_id,
            ),
        )
        conn.commit()

    def _build_triage_prompt(self, incident_data, score: float):
        incident_json = json.dumps(incident_data, indent=2)
        return f"""
You are a Kubernetes runtime security analyst. An ML anomaly detector (Isolation Forest,
score normalized 0.0-1.0) has flagged the following event.

Incident data:
{incident_json}

Anomaly score: {score:.3f}  (threshold for flagging: 0.5, max: 1.0)

Your tasks:
1. Determine if this is a genuine security incident or a false positive.
   Consider: Is this a known noisy Falco rule? Could this be expected container
   behaviour (e.g. init scripts, health checks, package installs)?
2. If genuine: assign severity (CRITICAL / HIGH / MEDIUM / LOW), identify the
   MITRE ATT&CK tactic (e.g. TA0002 Execution, TA0003 Persistence), write a
   2-3 sentence enriched description, and one concrete remediation step.
3. If false positive: briefly explain why.

Reply ONLY with a valid JSON object. No markdown, no preamble:
{{
  "verdict": "confirmed" or "rejected",
  "reason": "...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW" or null,
  "mitre_tactic": "TA00XX Name" or null,
  "enriched_description": "..." or null,
  "remediation": "..." or null
}}
""".strip()

    def _parse_triage_json(self, raw_text: str):
        text = (raw_text or "").strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:].strip()

        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            text = text[first : last + 1]

        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("Gemini response JSON is not an object")
        return data
