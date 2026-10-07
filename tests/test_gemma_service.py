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


def test_gemma_service_analyze_text_includes_upi_scam_patterns(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    captured_prompt = {}

    class UpiMockModels:
        def generate_content(self, model, contents, config):
            captured_prompt["text"] = contents

            assert model == settings.gemma_model
            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class UpiMockClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = UpiMockModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        UpiMockClient,
    )

    service = GemmaService()

    service.analyze_text(
        "Scan this QR code and enter your UPI PIN to receive your refund."
    )

    prompt = captured_prompt["text"]

    assert "UPI payment requests" in prompt
    assert "UPI PINs" in prompt
    assert "send money to receive money" in prompt
    assert "fake refunds" in prompt
    assert "fake KYC" in prompt
    assert "suspicious payment links" in prompt


def test_gemma_service_requires_api_key(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", None)

    with pytest.raises(ValueError, match="GEMINI_API_KEY is not configured."):
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
        "app.services.gemma_service.genai.types",
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


def test_gemma_service_analyze_image_includes_upi_scam_patterns(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-api-key")

    image_data = b"fake-payment-screenshot"
    image_base64 = base64.b64encode(image_data).decode("utf-8")

    captured_prompt = {}

    class MockPart:
        @staticmethod
        def from_bytes(data, mime_type):
            return {
                "data": data,
                "mime_type": mime_type,
            }

    class MockTypes:
        Part = MockPart

    class UpiImageMockModels:
        def generate_content(self, model, contents, config):
            captured_prompt["text"] = contents[0]

            assert model == settings.gemma_model
            assert len(contents) == 2
            assert config["response_mime_type"] == "application/json"
            assert config["response_schema"] is ScamAnalysis

            return MockResponse()

    class UpiImageMockClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"
            self.models = UpiImageMockModels()

    monkeypatch.setattr(
        "app.services.gemma_service.genai.Client",
        UpiImageMockClient,
    )
    monkeypatch.setattr(
        "app.services.gemma_service.genai.types",
        MockTypes,
    )

    service = GemmaService()

    service.analyze_image(
        image_base64=image_base64,
        mime_type="image/png",
    )

    prompt = captured_prompt["text"]

    assert "UPI PINs or payment authentication" in prompt
    assert "send money to receive money" in prompt
    assert "fake refunds or refund verification" in prompt
    assert "fake KYC or account verification" in prompt
    assert "suspicious QR-code or payment instructions" in prompt