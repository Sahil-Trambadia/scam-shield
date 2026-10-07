from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_analyze_text():
    response_data = {
        "risk_level": "HIGH",
        "scam_type": "phishing",
        "signals": [
            "otp_request",
            "urgency",
        ],
        "explanation": "The message requests an OTP and creates urgency.",
        "recommended_actions": [
            "Do not share the OTP.",
            "Do not respond to the message.",
        ],
    }

    class MockGemmaService:
        def analyze_text(self, text):
            assert text == "Send your OTP immediately."
            return response_data

    from app.api import analyze

    original_service = analyze.GemmaService
    analyze.GemmaService = MockGemmaService

    try:
        response = client.post(
            "/analyze/text",
            json={"text": "Send your OTP immediately."},
        )

        assert response.status_code == 200
        assert response.json() == response_data
    finally:
        analyze.GemmaService = original_service


def test_analyze_text_rejects_empty_text():
    response = client.post(
        "/analyze/text",
        json={"text": ""},
    )

    assert response.status_code == 422