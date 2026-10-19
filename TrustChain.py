from collections import defaultdict
from collections.abc import Iterable, Iterator
from itertools import chain
from typing import Any

from X509Parser import parse_certificate  #Use the parser's output directly.

ParsedCertificate = dict[str, Any]
CertificatePath = tuple[ParsedCertificate, ...]

class PathSearchLimitError(RuntimeError):
    """Too many issuer candidates were searched."""

def _fingerprint(cert: ParsedCertificate) -> str:
    """Identify the exact encoded certificate using the parser's SHA-256 hash."""
    return cert["fingerprint_sha256"]

def _issuer_priority(child: ParsedCertificate, candidate: ParsedCertificate) -> tuple[int, int]:
    """Sort possible issuers using the parser's AKI/SKI fields.

    AKI/SKI identifiers help the search but aren't proof of issuance. In
    particular, mismatched key identifiers do not eliminate a candidate.
    """
    child_aki = child["extensions"]["authority_key_identifier"] or {}
    candidate_ski = candidate["extensions"]["subject_key_identifier"] or {}

    aki_key = child_aki.get("key_identifier")
    ski_key = candidate_ski.get("key_identifier")

    #Known match -> high, missing ID -> medium, known mismatch -> low.
    if aki_key is None or ski_key is None:
        key_score = 1
    else:
        key_score = 2 if aki_key == ski_key else 0

    #An AKI may also identify the issuer certificate by its own issuer
    #(not subject) name together with its certificate serial number.
    aki_issuer_names = child_aki.get("authority_cert_issuer") or []
    aki_serial = child_aki.get("authority_cert_serial_number")
    issuer_cert_match = int(
        bool(aki_issuer_names)
        and aki_serial is not None
        and candidate["issuer"] in aki_issuer_names
        and candidate["serial_number"] == aki_serial
    )
    return (issuer_cert_match, key_score)

