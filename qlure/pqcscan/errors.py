from enum import Enum


class ScannerErrorType(str, Enum):
    TARGET_INVALID = "TARGET_INVALID"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    DNS_FAILURE = "DNS_FAILURE"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    TLS_NEGOTIATION_FAILURE = "TLS_NEGOTIATION_FAILURE"
    CERTIFICATE_PARSE_FAILURE = "CERTIFICATE_PARSE_FAILURE"
    PROTOCOL_UNSUPPORTED = "PROTOCOL_UNSUPPORTED"
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    TOOL_FAILURE = "TOOL_FAILURE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ScannerException(Exception):
    def __init__(self, error_type: ScannerErrorType, message: str):
        super().__init__(message)
        self.error_type = error_type
        self.message = message
