import base64

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_analyze_image():
    image_data = b"fake-image-data"
    image_base64 = base64.b64encode(image_data).decode("utf-8")

    response_data = {
        "risk_level": "HIGH",
        "scam_type": "phishing",
        "signals": [
            "otp_request",
            "urgency",
        ],
        "explanation": "The screenshot contains an OTP request and urgent language.",
        "recommended_actions": [
            "Do not share the OTP.",
            "Do not respond to the message.",
        ],
    }

    class MockGemmaService:
        def analyze_image(self, image_base64, mime_type):
            assert image_base64 == base64.b64encode(image_data).decode("utf-8")
            assert mime_type == "image/png"
            return response_data

    from app.api import analyze

    original_service = analyze.GemmaService
    analyze.GemmaService = MockGemmaService

    try:
        response = client.post(
            "/analyze/image",
            json={
                "image_base64": image_base64,
                "mime_type": "image/png",
            },
        )

        assert response.status_code == 200
        assert response.json() == response_data
    finally:
        analyze.GemmaService = original_service


def test_analyze_image_rejects_invalid_base64():
    response = client.post(
        "/analyze/image",
        json={
            "image_base64": "not-valid-base64!!!",
            "mime_type": "image/png",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid base64 image data."


def test_analyze_image_rejects_unsupported_mime_type():
    image_base64 = base64.b64encode(b"fake-image-data").decode("utf-8")

    response = client.post(
        "/analyze/image",
        json={
            "image_base64": image_base64,
            "mime_type": "application/pdf",
        },
    )

    assert response.status_code == 422