from __future__ import annotations

import json
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

        record = {
            "method": classified.method,
            "host": classified.host,
            "path": classified.path,
            "url": classified.url,
            "request_headers": classified.request_headers,
            "request_body": classified.request_body.decode(
                "utf-8", errors="replace"
            ),
            "response_status": classified.response_status,
            "response_headers": classified.response_headers,
            "response_body": classified.response_body.decode(
                "utf-8", errors="replace"
            ),
            "tags": classified.tags,
            "timestamp": classified.timestamp,
        }
        self.output_file.write(json.dumps(record) + "\n")
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
