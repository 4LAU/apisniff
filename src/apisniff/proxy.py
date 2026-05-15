from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from mitmproxy import http

from apisniff.adapters.mitmproxy_adapter import flow_to_captured
from apisniff.classify import Classifier
from apisniff.models import SessionStats
from apisniff.surface import (
    IMPORTANT_SURFACE_CATEGORIES,
    write_capture_context,
    write_surface_metadata,
)


class ApisniffAddon:
    def __init__(self, target_domain: str, output_path: str) -> None:
        self.classifier = Classifier(target_domain)
        self.output_path = Path(output_path)
        fd = os.open(self.output_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self.output_file = os.fdopen(fd, "a")
        self.output_path.chmod(0o600)
        self.domain = target_domain
        self.started_at = time.time()
        self.total_flows = 0
        self.kept_flows = 0
        self.api_flows = 0
        self.surface_flows = 0
        self.noise_flows = 0
        self.drop_counts: Counter[str] = Counter()

    def response(self, flow: http.HTTPFlow) -> None:
        self.total_flows += 1
        captured = flow_to_captured(flow)
        result = self.classifier.classify(captured)

        if result.action == "drop":
            self.drop_counts[result.category] += 1
            self._print_status()
            return

        if result.flow is None:
            self._print_status()
            return

        self.kept_flows += 1
        if result.category in {"business_api", "auth"}:
            self.api_flows += 1
        elif result.category in IMPORTANT_SURFACE_CATEGORIES:
            self.surface_flows += 1
        else:
            self.noise_flows += 1
        self.output_file.write(result.flow.to_jsonl() + "\n")
        self.output_file.flush()
        self._print_status()

    def _print_status(self) -> None:
        elapsed = int(time.time() - self.started_at)
        sys.stderr.write(
            f"\r  Captured: {self.kept_flows}  |  API: {self.api_flows}  |  "
            f"Surface: {self.surface_flows}  |  Noise: {self.noise_flows}  |  {elapsed}s"
        )
        sys.stderr.flush()

    def done(self) -> None:
        if self.output_file:
            self.output_file.close()

        from apisniff.bundle import read_capture_jsonl
        from apisniff.spec_classify import derive_surface_records

        flows = read_capture_jsonl(str(self.output_path)) if self.output_path.exists() else []
        context, records = derive_surface_records(flows, self.domain, self.classifier.context())
        write_capture_context(self.output_path.parent, context)
        write_surface_metadata(self.output_path.parent, records)

        duration = time.time() - self.started_at
        stats = SessionStats(
            domain=self.domain,
            started_at=datetime.fromtimestamp(self.started_at, tz=UTC).isoformat(),
            duration_seconds=round(duration, 1),
            total_flows=self.total_flows,
            kept_flows=self.kept_flows,
            dropped=dict(self.drop_counts),
            captured_flows=self.kept_flows,
            openapi_candidate_flows=self.api_flows,
            surface_flows=self.surface_flows,
            noise_flows=self.noise_flows,
        )
        session_path = self.output_path.parent / "session.json"
        session_path.write_text(json.dumps(stats.to_dict(), indent=2))


addons = [
    ApisniffAddon(
        target_domain=os.environ["APISNIFF_TARGET"],
        output_path=os.environ["APISNIFF_OUTPUT"],
    )
]
