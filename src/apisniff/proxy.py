from __future__ import annotations

import os
from pathlib import Path

from mitmproxy import http

from apisniff.adapters.mitmproxy_adapter import flow_to_captured
from apisniff.classify import Classifier


class ApisniffAddon:
    def __init__(self, target_domain: str, output_path: str) -> None:
        self.classifier = Classifier(target_domain)
        self.output_path = Path(output_path)
        self.output_file = open(self.output_path, "a")
        self.flow_count = 0
        self.kept_count = 0

    def response(self, flow: http.HTTPFlow) -> None:
        captured = flow_to_captured(flow)
        classified = self.classifier.classify(captured)

        self.flow_count += 1
        if classified is None:
            return

        self.kept_count += 1

        self.output_file.write(classified.to_jsonl() + "\n")
        self.output_file.flush()

    def done(self) -> None:
        if self.output_file:
            self.output_file.close()


addons = [
    ApisniffAddon(
        target_domain=os.environ.get("APISNIFF_TARGET", ""),
        output_path=os.environ.get("APISNIFF_OUTPUT", "/tmp/apisniff.jsonl"),
    )
]
