from __future__ import annotations


def join_header_values(grouped: dict[str, list[str]]) -> dict[str, str]:
    """Collapse multi-value headers into a single dict.

    Per RFC 9110, values are joined with ", " except set-cookie which uses
    newline so each directive remains individually parseable.
    """
    result: dict[str, str] = {}
    for key, values in grouped.items():
        if key == "set-cookie":
            result[key] = "\n".join(values)
        else:
            result[key] = ", ".join(values)
    return result
