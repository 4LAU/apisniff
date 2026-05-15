from pathlib import Path

import pytest

from apisniff.bundle import MAX_IMPORT_BYTES, load_flows


def test_load_flows_rejects_file_exceeding_import_limit(tmp_path: Path) -> None:
    p = tmp_path / "large.har"
    with p.open("wb") as f:
        f.truncate(MAX_IMPORT_BYTES + 1)

    with pytest.raises(ValueError) as exc_info:
        load_flows(str(p))

    message = str(exc_info.value)
    assert str(MAX_IMPORT_BYTES + 1) in message
    assert str(MAX_IMPORT_BYTES) in message
