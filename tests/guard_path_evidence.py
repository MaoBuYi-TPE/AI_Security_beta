"""Bounded, independent HTTP/1 request reassembly for encrypted Lab packet evidence.

This is an evidence parser, not a proxy: no bytes are sent or transformed. Missing SYN,
gaps, conflicting retransmissions and incomplete HTTP records make evidence unusable.
"""

import base64
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from tests.guard_path_cases import PATH_CASES

MAX_STREAM = 16 * 1024 * 1024


class EvidenceError(ValueError):
    """Capture cannot substantiate complete byte-preserving delivery."""


@dataclass
class Stream:
    first: int
    started: float
    peer: str
    destination: str
    pieces: list[tuple[int, bytes, float]] = field(default_factory=list)


def _chunk_end(data: bytes, start: int) -> int:
    position = start
    while True:
        end = data.find(b"\r\n", position)
        if end < 0:
            raise EvidenceError("incomplete chunk size")
        size_text = data[position:end].split(b";", 1)[0]
        if not size_text or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
            raise EvidenceError("invalid chunk size")
        size = int(size_text, 16)
        position = end + 2
        if size == 0:
            if data[position : position + 2] == b"\r\n":
                return position + 2
            end = data.find(b"\r\n\r\n", position)
            if end < 0:
                raise EvidenceError("incomplete trailers")
            return end + 4
        if size > MAX_STREAM or data[position + size : position + size + 2] != b"\r\n":
            raise EvidenceError("incomplete chunk")
        position += size + 2


def _requests(stream: Stream) -> list[dict[str, Any]]:
    data = bytearray()
    for sequence, piece, _time in sorted(stream.pieces):
        offset = sequence - stream.first
        if offset < 0 or offset > len(data) or offset + len(piece) > MAX_STREAM:
            raise EvidenceError("TCP gap or stream size limit")
        overlap = min(len(piece), len(data) - offset)
        if data[offset : offset + overlap] != piece[:overlap]:
            raise EvidenceError("conflicting TCP retransmission")
        data.extend(piece[overlap:])
    raw, position, results = bytes(data), 0, []
    while position < len(raw):
        first_byte = stream.first + position
        received_at = min(
            t for seq, piece, t in stream.pieces if seq <= first_byte < seq + len(piece)
        )
        end = raw.find(b"\r\n\r\n", position)
        if end < 0 or end - position > 65536:
            raise EvidenceError("incomplete or oversized HTTP head")
        lines = raw[position:end].split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) != 3 or parts[2] not in {b"HTTP/1.0", b"HTTP/1.1"}:
            raise EvidenceError("invalid request line")
        try:
            method, target = (part.decode("ascii") for part in parts[:2])
        except UnicodeDecodeError as exc:
            raise EvidenceError("non-ASCII request target") from exc
        headers: dict[bytes, list[bytes]] = {}
        for line in lines[1:]:
            key, separator, value = line.partition(b":")
            if not separator:
                raise EvidenceError("invalid header")
            headers.setdefault(key.lower(), []).append(value.strip())
        position = end + 4
        length, transfer = headers.get(b"content-length", []), headers.get(b"transfer-encoding", [])
        if transfer:
            if length or transfer != [b"chunked"]:
                raise EvidenceError("ambiguous request framing")
            position = _chunk_end(raw, position)
        elif length:
            if len(length) != 1 or not length[0].isdigit() or len(length[0]) > 9:
                raise EvidenceError("invalid content length")
            position += int(length[0])
        if position > len(raw):
            raise EvidenceError("incomplete request body")
        results.append(
            {
                "time": received_at,
                "peer": stream.peer,
                "destination": stream.destination,
                "method": method,
                "target": target,
                "path": target.partition("?")[0],
                "request_line_hex": lines[0].hex(),
            }
        )
    return results


def received_requests(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    active: dict[tuple[str, str, int, int], Stream] = {}
    streams: list[Stream] = []
    for event in events:
        key = (
            str(event["source"]),
            str(event["destination"]),
            int(event["sport"]),
            int(event["dport"]),
        )
        sequence, flags = int(event["seq"]), int(event["flags"])
        payload = base64.b64decode(event["payload"], validate=True)
        if flags & 2:
            # A retransmitted SYN belongs to the same connection.
            previous = active.get(key)
            if previous is None or previous.first != sequence + 1:
                active[key] = Stream(sequence + 1, float(event["time"]), key[0], key[1])
                streams.append(active[key])
            sequence += 1
        if payload:
            stream = active.get(key)
            if stream is None:
                raise EvidenceError("missing TCP SYN")
            stream.pieces.append((sequence, payload, float(event["time"])))
    return [record for stream in streams for record in _requests(stream)]


PUBLIC_FIELDS = frozenset(
    {
        "method",
        "path",
        "policy_version",
        "decision",
        "reason",
        "detail",
        "forwarded",
        "received",
        "status",
    }
)


def public_echo_rows(
    version: str,
    decisions: list[dict[str, Any]],
    telemetry: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    results: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Export only the closed synthetic corpus; arbitrary scanner paths never enter fixtures."""
    if version not in {"strict-1", "encoded-params-1"}:
        raise EvidenceError("unsupported fixture policy")
    if [entry.get("path") for entry in decisions] != [case.path for case in PATH_CASES]:
        raise EvidenceError("cannot export paths outside the fixed synthetic corpus")
    sent = [entry["path"] for entry in telemetry if entry["e"] == "request"]
    received = [entry["target"] for entry in receipts]
    if sent != received:
        raise EvidenceError("cannot export unverified target receipts")
    rows = []
    for index, (case, decision) in enumerate(zip(PATH_CASES, decisions, strict=True)):
        reason = case.strict_reason if version == "strict-1" else case.encoded_reason
        detail = case.strict_detail if version == "strict-1" else case.encoded_detail
        allowed = reason is None
        if version == "encoded-params-1" and allowed and "%" in case.path:
            detail = "encoded-route-parameter"
        if (
            decision.get("method") != "GET"
            or decision.get("policy_version") != version
            or decision.get("reason") != reason
            or decision.get("detail") != detail
            or decision.get("decision") != ("allow" if allowed else "deny")
        ):
            raise EvidenceError("recorded decision differs from fixed expectations")
        if sent.count(case.path) != int(allowed):
            raise EvidenceError("recorded forwarding count differs")
        status = results[str(index)]["status"]
        if status != (200 if allowed else 403):
            raise EvidenceError("unexpected probe status")
        rows.append(
            {
                "method": "GET",
                "path": case.path,
                "policy_version": version,
                "decision": "allow" if allowed else "deny",
                "reason": reason,
                "detail": detail,
                "forwarded": allowed,
                "received": allowed,
                "status": status,
            }
        )
    return rows
