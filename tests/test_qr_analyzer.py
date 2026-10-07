import base64
import unittest

import cv2
import numpy as np

from app.services.qr_analyzer import QRAnalyzer


class TestQRAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = QRAnalyzer()

    def create_qr_base64(self, payload: str) -> str:
        generator = cv2.QRCodeEncoder_create()
        qr_image = generator.encode(payload)

        # Enlarge the generated QR code so QRCodeDetector can reliably
        # detect and decode it.
        qr_image = cv2.resize(
            qr_image,
            None,
            fx=10,
            fy=10,
            interpolation=cv2.INTER_NEAREST,
        )

        # Add a white quiet zone around the QR code.
        qr_image = cv2.copyMakeBorder(
            qr_image,
            20,
            20,
            20,
            20,
            cv2.BORDER_CONSTANT,
            value=255,
        )

        success, buffer = cv2.imencode(".png", qr_image)

        if not success:
            raise RuntimeError("Failed to create test QR image.")

        return base64.b64encode(buffer.tobytes()).decode("utf-8")

    def test_decode_qr_payload(self):
        image_base64 = self.create_qr_base64(
            "https://example.com/payment"
        )

        result = self.analyzer.decode(image_base64)

        self.assertEqual(
            result,
            ["https://example.com/payment"],
        )

    def test_no_qr_code_returns_empty_list(self):
        image = np.full((200, 200, 3), 255, dtype=np.uint8)

        success, buffer = cv2.imencode(".png", image)

        self.assertTrue(success)

        image_base64 = base64.b64encode(
            buffer.tobytes()
        ).decode("utf-8")

        result = self.analyzer.decode(image_base64)

        self.assertEqual(result, [])

    def test_invalid_base64_raises_error(self):
        with self.assertRaises(ValueError):
            self.analyzer.decode("not-valid-base64")

    def test_invalid_image_raises_error(self):
        image_base64 = base64.b64encode(
            b"this is not an image"
        ).decode("utf-8")

        with self.assertRaises(ValueError):
            self.analyzer.decode(image_base64)

    def test_http_url_qr_signal(self):
        image_base64 = self.create_qr_base64(
            "http://example.com/verify"
        )

        signals = self.analyzer.analyze(image_base64)

        self.assertIn(
            "QR code contains a URL",
            signals,
        )

        self.assertIn(
            "QR code contains an HTTP URL",
            signals,
        )

    def test_payment_qr_signal(self):
        image_base64 = self.create_qr_base64(
            "upi://pay?pa=scammer@upi&am=5000"
        )

        signals = self.analyzer.analyze(image_base64)

        self.assertIn(
            "QR code contains payment-related content",
            signals,
        )

    def test_credential_qr_signal(self):
        image_base64 = self.create_qr_base64(
            "https://example.com/verify?otp=123456"
        )

        signals = self.analyzer.analyze(image_base64)

        self.assertIn(
            "QR code contains credential or verification-related content",
            signals,
        )


if __name__ == "__main__":
    unittest.main()