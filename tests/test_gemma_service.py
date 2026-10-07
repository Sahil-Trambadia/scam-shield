import base64

import pytest

from app.config import settings
from app.models.scam_analysis import ScamAnalysis
from app.services.gemma_service import GemmaService


class MockResponse:
    text = """
    {
        "risk_level": "high",
        "scam_type": "phishing",
        "signals": [
            "otp_request",
            "urgency",
            "prize_claim",
            "otp_request"
        ],
        "explanation": "The message asks for an OTP and creates urgency around a prize.",
        "recommended_actions": [
            "Do not respond to the message."
        ]
    }
    """


class MockModels:
    def generate_content(self, model, contents, config):
        assert model == settings.gemma_model
        assert config["response_mime_type"] == "application/json"
        assert config["response_schema"] is ScamAnalysis

        return MockResponse()


class MockClient:
    def __init__(self, api_key):
        assert api_key == "test-api-key"
        self.models = MockModels()


def test_gemma_service_analyze_text(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")
    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        MockClient,
    )

    service = GemmaService()

    result = service.analyze_text(
        "Send your OTP immediately to receive your prize."
    )

    assert result.risk_level == "HIGH"
    assert result.scam_type == "phishing"
    assert result.signals == [
        "otp_request",
        "urgency",
        "prize_claim",
    ]
    assert (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    ) in result.recommended_actions


def test_gemma_service_requires_api_key(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", None)

    with pytest.raises(
        ValueError,
        match="GEMINI_API_KEY is not configured.",
    ):
        GemmaService()


def test_gemma_service_analyze_image(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    image_data = b"fake-image-data"
    image_base64 = base64.b64encode(image_data).decode("utf-8")

    class MockPart:
        @staticmethod
        def from_bytes(data, mime_type):
            assert data == image_data
            assert mime_type == "image/png"

            return {
                "data": data,
                "mime_type": mime_type,
            }

    class MockTypes:
        Part = MockPart

    class MockImageModels:
        def generate_content(self, model, contents, config):
            assert model == settings.gemma_model
            assert len(contents) == 2
            assert "You are Scam Shield" in contents[0]

            assert contents[1]["data"] == image_data
            assert contents[1]["mime_type"] == "image/png"

            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class MockImageClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = MockImageModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        MockImageClient,
    )

    monkeypatch.setattr(
        "app.services.gemma_service.types",
        MockTypes,
    )

    service = GemmaService()

    result = service.analyze_image(
        image_base64=image_base64,
        mime_type="image/png",
    )

    assert result.risk_level == "HIGH"
    assert result.scam_type == "phishing"
    assert result.signals == [
        "otp_request",
        "urgency",
        "prize_claim",
    ]
    assert (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    ) in result.recommended_actions


def test_gemma_service_analyze_text_includes_url_evidence(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    captured = {}

    class MockURLModels:
        def generate_content(self, model, contents, config):
            captured["prompt"] = contents

            assert model == settings.gemma_model
            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class MockURLClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = MockURLModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        MockURLClient,
    )

    service = GemmaService()

    result = service.analyze_text(
        "Your refund is ready. "
        "Visit http://192.168.1.20:8080/upi/verify"
    )

    prompt = captured["prompt"]

    assert result.risk_level == "HIGH"

    assert "http://192.168.1.20:8080/upi/verify" in prompt
    assert "URL uses HTTP instead of HTTPS" in prompt
    assert "URL uses an IP address instead of a domain" in prompt
    assert "URL uses a non-standard port" in prompt
    assert (
        "URL contains payment, verification, account, or "
        "credential-related terms"
    ) in prompt


def test_gemma_service_analyze_text_without_url_reports_no_url_evidence(
    monkeypatch,
):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    captured = {}

    class MockNoURLModels:
        def generate_content(self, model, contents, config):
            captured["prompt"] = contents

            assert model == settings.gemma_model
            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class MockNoURLClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = MockNoURLModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        MockNoURLClient,
    )

    service = GemmaService()

    result = service.analyze_text(
        "Hello, this is a normal message without a link."
    )

    prompt = captured["prompt"]

    assert result.risk_level == "HIGH"
    assert "No URLs detected." in prompt
    assert "No suspicious URL characteristics detected." in prompt


def test_gemma_service_analyze_image_includes_qr_evidence(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    captured = {}

    class MockQRModels:
        def generate_content(self, model, contents, config):
            captured["prompt"] = contents[0]

            assert model == settings.gemma_model
            assert len(contents) == 2

            image_part = contents[1]
            assert image_part.inline_data.data == b"fake-image-data"
            assert image_part.inline_data.mime_type == "image/png"

            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class MockQRClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = MockQRModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        MockQRClient,
    )

    monkeypatch.setattr(
        "app.services.gemma_service.QRAnalyzer.decode",
        lambda self, image_base64: [
            "upi://pay?pa=scammer@upi&am=5000"
        ],
    )

    monkeypatch.setattr(
        "app.services.gemma_service.QRAnalyzer.analyze",
        lambda self, image_base64: [
            "QR code contains payment-related content"
        ],
    )

    image_data = b"fake-image-data"
    image_base64 = base64.b64encode(image_data).decode("utf-8")

    service = GemmaService()

    result = service.analyze_image(
        image_base64=image_base64,
        mime_type="image/png",
    )

    prompt = captured["prompt"]

    assert result.risk_level == "HIGH"
    assert "Locally decoded QR-code payloads:" in prompt
    assert "upi://pay?pa=scammer@upi&am=5000" in prompt
    assert "Locally detected QR-code characteristics:" in prompt
    assert "QR code contains payment-related content" in prompt


def test_gemma_service_analyze_image_without_qr_reports_no_qr_evidence(
    monkeypatch,
):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    captured = {}

    class MockNoQRModels:
        def generate_content(self, model, contents, config):
            captured["prompt"] = contents[0]

            assert model == settings.gemma_model
            assert len(contents) == 2

            image_part = contents[1]
            assert image_part.inline_data.data == b"fake-image-data"
            assert image_part.inline_data.mime_type == "image/png"

            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class MockNoQRClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = MockNoQRModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        MockNoQRClient,
    )

    monkeypatch.setattr(
        "app.services.gemma_service.QRAnalyzer.decode",
        lambda self, image_base64: [],
    )

    monkeypatch.setattr(
        "app.services.gemma_service.QRAnalyzer.analyze",
        lambda self, image_base64: [],
    )

    image_data = b"fake-image-data"
    image_base64 = base64.b64encode(image_data).decode("utf-8")

    service = GemmaService()

    result = service.analyze_image(
        image_base64=image_base64,
        mime_type="image/png",
    )

    prompt = captured["prompt"]

    assert result.risk_level == "HIGH"
    assert "- No QR-code payload detected." in prompt
    assert "- No suspicious QR-code characteristics detected." in prompt