from __future__ import annotations

import json
import os
import time
from collections import Counter
from pathlib import Path

from mitmproxy import http

from apisniff.adapters.mitmproxy_adapter import flow_to_captured
from apisniff.classify import Classifier
from apisniff.models import SessionStats


class ApisniffAddon:
    def __init__(self, target_domain: str, output_path: str) -> None:
        self.classifier = Classifier(target_domain)
        self.output_path = Path(output_path)
        self.output_file = open(self.output_path, "a")
        self.domain = target_domain
        self.started_at = time.time()
        self.total_flows = 0
        self.kept_flows = 0
        self.drop_counts: Counter[str] = Counter()

    def response(self, flow: http.HTTPFlow) -> None:
        captured = flow_to_captured(flow)
        result = self.classifier.classify(captured)

        self.total_flows += 1
        if result.action == "drop":
            self.drop_counts[result.category] += 1
            return

        self.kept_flows += 1
        self.output_file.write(result.flow.to_jsonl() + "\n")
        self.output_file.flush()

    def done(self) -> None:
        if self.output_file:
            self.output_file.close()

        duration = time.time() - self.started_at
        from datetime import datetime, timezone
        stats = SessionStats(
            domain=self.domain,
            started_at=datetime.fromtimestamp(self.started_at, tz=timezone.utc).isoformat(),
            duration_seconds=round(duration, 1),
            total_flows=self.total_flows,
            kept_flows=self.kept_flows,
            dropped=dict(self.drop_counts),
        )
        session_path = self.output_path.parent / "session.json"
        session_path.write_text(json.dumps(stats.to_dict(), indent=2))


addons = [
    ApisniffAddon(
        target_domain=os.environ.get("APISNIFF_TARGET", ""),
        output_path=os.environ.get("APISNIFF_OUTPUT", "/tmp/apisniff.jsonl"),
    )
]
