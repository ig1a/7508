"""Hybrid payload scanner using detect-secrets and Microsoft Presidio.

The scanner inspects JSON string values and derived variants (base64-decoded
text and spaced-character runs). It never reads evaluation canaries.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from threading import RLock
from typing import Any

from security_gateway.models import DetectionFinding, DetectionReport

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])")
_SPACED_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?:[ \t_-]+)){7,}[A-Za-z0-9](?![A-Za-z0-9])")
# Entropy detectors should only inspect token-like candidates, never whole prose lines.
_TOKEN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9])")
_ENTROPY_TYPES = {"Base64 High Entropy String", "Hex High Entropy String"}
# A high-entropy match is supporting evidence, not proof of confidentiality.
_SECRET_CONTEXT_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|secret|token|password|credential|authorization|"
    r"access[_ -]?key|private[_ -]?key|client[_ -]?secret|database[_ -]?url)\b"
)
_DATABASE_PASSWORD_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
    r"[^/@\s]*:([^/@\s]+)@[^\s]+"
)
_HKID_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{6}\([0-9A]\)(?![A-Za-z0-9])")
_PII_TYPES = {
    "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IBAN_CODE",
    "UK_NHS", "US_PASSPORT", "UK_NINO", "SG_NRIC_FIN", "AU_TFN",
}
_PII_WITH_CONTEXT = {
    "US_DRIVER_LICENSE": ("driver", "license", "licence"),
    "US_BANK_NUMBER": ("bank", "account number", "routing number"),
}


def _hk_id_valid(value: str) -> bool:
    """Validate the checksum for a one-letter Hong Kong identity number."""
    if not _HKID_RE.fullmatch(value):
        return False
    letter = value[0]
    digits = [int(c) for c in value[1:7]]
    total = 36 * 9 + (ord(letter) - 55) * 8 + sum(d * (7 - i) for i, d in enumerate(digits))
    check = (11 - total % 11) % 11
    return value[-2] == ("A" if check == 10 else str(check))


def _contains_nonplaceholder_db_password(text: str) -> bool:
    for match in _DATABASE_PASSWORD_RE.finditer(text):
        password = match.group(1)
        if password.lower() not in {"password", "changeme", "placeholder", "replace_me"}:
            return True
    return False


def _strong_opaque_token(token: str) -> bool:
    # Hex digests/checksums are not evidence of a secret without context.
    if len(token) < 36 or re.fullmatch(r"[a-fA-F0-9]+", token):
        return False
    return bool(re.search(r"[a-z]", token) and re.search(r"[A-Z]", token)
                and re.search(r"\d", token) and len(set(token)) >= 12)


def _public_placeholder(text: str) -> bool:
    # Exact placeholder values only; a real password prefixed "password..."
    # must never be exempted because a message claims to be an example.
    literal = re.search(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*[\"']?([^\s,;#\"']+)",
        text,
    )
    if literal:
        value = literal.group(1)
        if (value.lower() in {"changeme", "replace_me", "placeholder", "password"}
                or re.fullmatch(r"<[^>]+>", value)):
            return True
    return bool(re.search(
        r"(?i)://user:password@localhost(?::\d+)?(?:/|$)", text
    ))


def _is_high_entropy_secret(line: str, match: re.Match[str]) -> bool:
    token = match.group(0)
    if _public_placeholder(line) and token.lower() in {"changeme", "password"}:
        return False
    # Require proximity to a credential label, not an unrelated keyword in the
    # same sentence (for instance a public SHA-256 checksum next to an AWS tutorial).
    prefix = line[max(0, match.start() - 45):match.start()]
    if re.search(r"(?i)(?:sha[- ]?256|checksum|digest)\s*[:=]?\s*$", prefix):
        return False
    return bool(_SECRET_CONTEXT_RE.search(prefix)) or _strong_opaque_token(token)



class DetectionUnavailable(RuntimeError):
    pass


def _string_values(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for child in value.values():
            found.extend(_string_values(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(_string_values(child))
    return found


def extract_payload_texts(payload: bytes) -> list[str]:
    """Extract strings from a non-empty, valid JSON outbound payload.

    OutboundRequest.body is expected to be JSON. Empty, invalid UTF-8, malformed
    JSON, and non-object/non-array roots are inspection failures; they must not
    be silently treated as clean raw text.
    """
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise ValueError("PAYLOAD_EMPTY")

    raw = bytes(payload).decode("utf-8", errors="strict")
    if not raw.strip():
        raise ValueError("PAYLOAD_EMPTY")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("PAYLOAD_INVALID_JSON") from exc

    if not isinstance(parsed, (dict, list)):
        raise ValueError("PAYLOAD_INVALID_ROOT_TYPE")

    # The serialized outbound body includes fixed transport instructions that are
    # not user data (model tag, generation options, message role names).
    # Never feed those into entropy/PII recognizers: that generated recurring
    # false alarms on every request, including PUBLIC-only sessions.
    # All conversation text is scanned, including system and assistant responses;
    # any additional/unknown fields are also inspected to avoid an egress bypass.
    if isinstance(parsed, dict) and "messages" in parsed:
        messages = parsed["messages"]
        if not isinstance(messages, list):
            raise ValueError("PAYLOAD_INVALID_MESSAGES")
        values: list[str] = []
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("PAYLOAD_INVALID_MESSAGES")
            if "content" in message:
                values.extend(_string_values(message["content"]))
            for key, value in message.items():
                if key not in {"content", "role"}:
                    values.extend(_string_values(value))
        for key, value in parsed.items():
            if key not in {"messages", "model", "options", "stream"}:
                values.extend(_string_values(value))
    else:
        values = _string_values(parsed)
    return list(dict.fromkeys(values))


def _derived_variants(text: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = []
    for match in _BASE64_RE.finditer(text):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) > 0.9:
            variants.append((decoded, "base64_decoded"))
    for match in _SPACED_TOKEN_RE.finditer(text):
        variants.append((re.sub(r"\s+", "", match.group(0)), "spaced_compact"))
    return variants


class HybridPayloadScanner:
    """Lazy-loaded detector wrapper; detector failures are reported as incomplete."""

    def __init__(self, language: str = "en"):
        self.language = language
        self._lock = RLock()
        self._secret_scan_line = None
        self._secret_default_settings = None
        self._presidio_analyzer = None
        self._initialised = False
        self._initialise_error: str | None = None

    def _initialise(self) -> None:
        with self._lock:
            if self._initialised:
                if self._initialise_error:
                    raise DetectionUnavailable(self._initialise_error)
                return
            self._initialised = True
            try:
                from detect_secrets.core.scan import scan_line
                from detect_secrets.settings import default_settings
                self._secret_scan_line = scan_line
                self._secret_default_settings = default_settings
            except Exception as exc:
                self._initialise_error = f"DETECT_SECRETS_UNAVAILABLE:{type(exc).__name__}"
                raise DetectionUnavailable(self._initialise_error) from exc

            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_analyzer.nlp_engine import NlpEngineProvider

                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": self.language, "model_name": "en_core_web_sm"}],
                }
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()
                self._presidio_analyzer = AnalyzerEngine(
                    nlp_engine=nlp_engine,
                    supported_languages=[self.language],
                )
            except Exception as exc:
                self._initialise_error = f"PRESIDIO_UNAVAILABLE:{type(exc).__name__}"
                raise DetectionUnavailable(self._initialise_error) from exc

    def scan(self, payload: bytes, *, additional_texts: tuple[str, ...] = ()) -> DetectionReport:
        try:
            self._initialise()
            try:
                texts = extract_payload_texts(payload)
            except ValueError as exc:
                return DetectionReport(inspection_complete=False, error_code=str(exc))
            texts.extend(text for text in additional_texts if isinstance(text, str) and text)
            texts = list(dict.fromkeys(texts))
            findings: set[DetectionFinding] = set()
            candidates: list[tuple[str, str]] = []
            for text in texts:
                candidates.append((text, "raw"))
                candidates.extend(_derived_variants(text))

            for text, variant in candidates:
                for line in text.splitlines() or [text]:
                    if not line.strip():
                        continue
                    try:
                        # Use detect-secrets' configured default plugins.
                        with self._secret_default_settings():
                            line_findings = list(self._secret_scan_line(line))
                    except Exception as exc:
                        return DetectionReport(inspection_complete=False,
                                               error_code=f"DETECT_SECRETS_SCAN_ERROR:{type(exc).__name__}")

                    # Format-specific detectors (AWS keys, private keys, tokens, etc.)
                    # can inspect the full line. High-entropy detectors are more prone
                    # to false positives on natural-language prose, so accept their
                    # result only when an isolated token-like candidate also triggers.
                    for secret in line_findings:
                        secret_type = str(getattr(secret, "type", "SECRET"))
                        if secret_type not in _ENTROPY_TYPES:
                            # A literal sample username/password and a documented
                            # placeholder assignment are not actual credentials.
                            if secret_type in {"Basic Auth Credentials", "Secret Keyword"} and _public_placeholder(line):
                                continue
                            findings.add(DetectionFinding("detect-secrets", secret_type, variant))

                    for match in _TOKEN_CANDIDATE_RE.finditer(line):
                        token = match.group(0)
                        try:
                            with self._secret_default_settings():
                                token_findings = list(self._secret_scan_line(token))
                        except Exception as exc:
                            return DetectionReport(inspection_complete=False,
                                                   error_code=f"DETECT_SECRETS_SCAN_ERROR:{type(exc).__name__}")
                        for secret in token_findings:
                            secret_type = str(getattr(secret, "type", "SECRET"))
                            if secret_type in _ENTROPY_TYPES and _is_high_entropy_secret(line, match):
                                findings.add(DetectionFinding("detect-secrets", secret_type, variant))

                try:
                    entities = self._presidio_analyzer.analyze(text=text, language=self.language)
                except Exception as exc:
                    return DetectionReport(inspection_complete=False,
                                           error_code=f"PRESIDIO_SCAN_ERROR:{type(exc).__name__}")
                for entity in entities:
                    entity_type = str(entity.entity_type)
                    score = float(entity.score)
                    if entity_type in _PII_TYPES:
                        # A recognized address/telephone/identity is meaningful;
                        # avoid weak matches of short public numeric literals.
                        if score >= 0.65:
                            findings.add(DetectionFinding("presidio", entity_type, variant, score))
                    elif entity_type in _PII_WITH_CONTEXT:
                        if score >= 0.85 and any(
                            hint in text.lower() for hint in _PII_WITH_CONTEXT[entity_type]
                        ):
                            findings.add(DetectionFinding("presidio", entity_type, variant, score))
                    # Single PERSON / LOCATION / DATE_TIME / IP_ADDRESS / UUID /
                    # NRP / ORGANIZATION labels are not themselves proof of PII.

                for match in _HKID_RE.finditer(text):
                    if _hk_id_valid(match.group(0)):
                        findings.add(DetectionFinding("hkid-checksum", "HKID", variant, 1.0))
                if _contains_nonplaceholder_db_password(text):
                    findings.add(DetectionFinding("credential-pattern", "DATABASE_PASSWORD", variant, 1.0))

            return DetectionReport(findings=tuple(sorted(
                findings, key=lambda x: (x.detector, x.entity_type, x.source_variant)
            )))
        except (UnicodeDecodeError, DetectionUnavailable) as exc:
            code = str(exc) if isinstance(exc, DetectionUnavailable) else "PAYLOAD_INVALID_UTF8"
            return DetectionReport(inspection_complete=False, error_code=code)
        except Exception as exc:  # security boundary: never fail open
            return DetectionReport(inspection_complete=False, error_code=f"SCANNER_FAILURE:{type(exc).__name__}")
