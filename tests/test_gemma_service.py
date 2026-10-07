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