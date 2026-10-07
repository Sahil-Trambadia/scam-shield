import base64

import cv2
import numpy as np


class QRAnalyzer:
    """Decode QR codes from image data without visiting decoded destinations."""

    def decode(self, image_base64: str) -> list[str]:
        """Decode all detectable QR-code payloads from a base64 image."""
        try:
            image_bytes = base64.b64decode(image_base64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid base64 image data.") from exc

        image_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None:
            raise ValueError("Unable to decode image data.")

        detector = cv2.QRCodeDetector()

        try:
            decoded, _, _ = detector.detectAndDecode(image)
        except cv2.error as exc:
            raise ValueError("Unable to analyze image for QR codes.") from exc

        if not decoded:
            return []

        return [decoded]

    def analyze(self, image_base64: str) -> list[str]:
        """Return safe local observations about decoded QR-code content."""
        payloads = self.decode(image_base64)

        signals = []

        for payload in payloads:
            normalized = payload.strip().lower()

            if normalized.startswith(("http://", "https://")):
                signals.append("QR code contains a URL")

                if normalized.startswith("http://"):
                    signals.append("QR code contains an HTTP URL")

            if any(
                term in normalized
                for term in (
                    "upi://",
                    "upi/",
                    "pay",
                    "payment",
                    "collect",
                    "intent://",
                )
            ):
                signals.append("QR code contains payment-related content")

            if any(
                term in normalized
                for term in (
                    "otp",
                    "pin",
                    "password",
                    "login",
                    "verify",
                    "verification",
                    "kyc",
                    "credential",
                )
            ):
                signals.append(
                    "QR code contains credential or verification-related content"
                )

        return self._deduplicate(signals)

    @staticmethod
    def _deduplicate(signals: list[str]) -> list[str]:
        normalized = []
        seen = set()

        for signal in signals:
            key = signal.casefold()

            if key not in seen:
                seen.add(key)
                normalized.append(signal)

        return normalized