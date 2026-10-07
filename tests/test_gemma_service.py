import base64

import pytest

from app.config import settings
from app.models.scam_analysis import ScamAnalysis
from app.services.gemma_service import GemmaService


class MockResponse:
    text = """
    {
        "risk_level": "HIGH",
        "scam_type": "phishing",
        "signals": [
            "otp_request",
            "urgency",
            "prize_claim"
        ],
        "explanation": "The message asks for an OTP and creates urgency around a prize.",
        "recommended_actions": [
            "Do not share the OTP.",
            "Do not respond to the message."
        ]
    }
    """


class MockModels:
    def generate_content(self, model, contents, config):
        assert model == settings.gemma_model
        assert "You are Scam Shield" in contents
        assert "Send your OTP immediately to receive your prize." in contents
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
    assert "otp_request" in result.signals


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
    assert "otp_request" in result.signals