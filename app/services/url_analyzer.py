import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)

COMMON_URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

SUSPICIOUS_PATH_TERMS = {
    "login",
    "verify",
    "verification",
    "kyc",
    "refund",
    "payment",
    "pay",
    "otp",
    "upi",
    "account",
    "security",
    "confirm",
    "claim",
}


class URLAnalyzer:
    """Extract URLs and identify observable suspicious URL characteristics."""

    def extract_urls(self, text: str) -> list[str]:
        """Return unique HTTP(S) URLs found in text while preserving order."""

        urls = []
        seen = set()

        for match in URL_PATTERN.findall(text):
            url = match.rstrip(".,!?;:)]}\"'")

            if url not in seen:
                seen.add(url)
                urls.append(url)

        return urls

    def analyze(self, text: str) -> list[str]:
        """Return evidence-based signals for URLs found in text."""

        signals = []

        for url in self.extract_urls(text):
            parsed = urlparse(url)

            if not parsed.hostname:
                continue

            hostname = parsed.hostname.lower()
            path_and_query = (
                f"{parsed.path}?{parsed.query}"
                if parsed.query
                else parsed.path
            ).lower()

            if parsed.scheme.lower() == "http":
                signals.append("URL uses HTTP instead of HTTPS")

            if hostname in COMMON_URL_SHORTENERS:
                signals.append("URL uses a known URL shortener")

            if self._is_ip_address(hostname):
                signals.append("URL uses an IP address instead of a domain")

            if parsed.port is not None:
                signals.append("URL uses a non-standard port")

            if hostname.count(".") >= 3:
                signals.append("URL contains multiple nested subdomains")

            if "@" in url:
                signals.append("URL contains an @ symbol")

            if "%" in url:
                signals.append("URL contains percent-encoded characters")

            if any(term in path_and_query for term in SUSPICIOUS_PATH_TERMS):
                signals.append(
                    "URL contains payment, verification, account, or "
                    "credential-related terms"
                )

        return self._deduplicate(signals)

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Return True when the hostname is an IPv4-style address."""

        parts = hostname.split(".")

        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    @staticmethod
    def _deduplicate(signals: list[str]) -> list[str]:
        """Remove duplicate signals while preserving their order."""

        normalized = []
        seen = set()

        for signal in signals:
            key = signal.casefold()

            if key not in seen:
                seen.add(key)
                normalized.append(signal)

        return normalized