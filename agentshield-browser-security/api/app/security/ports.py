from __future__ import annotations


class PortPolicy:
    def __init__(self, spec: str) -> None:
        self._ranges = parse_port_spec(spec)

    def is_allowed(self, port: int) -> bool:
        return any(start <= port <= end for start, end in self._ranges)


def parse_port_spec(spec: str) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []

    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue

        if "-" in part:
            pieces = part.split("-", 1)
            if len(pieces) != 2 or not pieces[0].isdigit() or not pieces[1].isdigit():
                raise ValueError(f"invalid port range: {part}")
            start, end = int(pieces[0]), int(pieces[1])
        else:
            if not part.isdigit():
                raise ValueError(f"invalid port: {part}")
            start = end = int(part)

        if start < 1 or end > 65535 or start > end:
            raise ValueError(f"port range out of bounds: {part}")

        ranges.append((start, end))

    if not ranges:
        raise ValueError("at least one allowed port is required")

    return tuple(ranges)
