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


def test_analyze_upi_pin_scam():
    response_data = {
        "risk_level": "CRITICAL",
        "scam_type": "UPI payment scam",
        "signals": [
            "upi_pin_request",
            "urgency",
            "payment_request",
        ],
        "explanation": (
            "The message asks the user to enter a UPI PIN to receive money."
        ),
        "recommended_actions": [
            "Do not enter or share your UPI PIN.",
            "Do not make the requested payment.",
        ],
    }

    class MockGemmaService:
        def analyze_text(self, text):
            assert "upi pin" in text.lower()
            assert "receive" in text.lower()
            assert "money" in text.lower()
            return response_data

    from app.api import analyze

    original_service = analyze.GemmaService
    analyze.GemmaService = MockGemmaService

    try:
        response = client.post(
            "/analyze/text",
            json={
                "text": (
                    "Your refund is waiting. Enter your UPI PIN to "
                    "receive the money immediately."
                )
            },
        )

        assert response.status_code == 200
        assert response.json()["risk_level"] == "CRITICAL"
        assert response.json()["scam_type"] == "UPI payment scam"
        assert "upi_pin_request" in response.json()["signals"]
    finally:
        analyze.GemmaService = original_service


def test_analyze_send_money_to_receive_money_scam():
    response_data = {
        "risk_level": "HIGH",
        "scam_type": "payment scam",
        "signals": [
            "send_money_to_receive_money",
            "urgent_payment",
        ],
        "explanation": (
            "The message claims that money must be sent before a refund "
            "or payment can be received."
        ),
        "recommended_actions": [
            "Do not send money.",
            "Verify the request through an official channel.",
        ],
    }

    class MockGemmaService:
        def analyze_text(self, text):
            assert "send ₹500" in text.lower()
            assert "receive ₹5,000" in text.lower()
            return response_data

    from app.api import analyze

    original_service = analyze.GemmaService
    analyze.GemmaService = MockGemmaService

    try:
        response = client.post(
            "/analyze/text",
            json={
                "text": (
                    "Send ₹500 through UPI to receive ₹5,000 refund "
                    "immediately."
                )
            },
        )

        assert response.status_code == 200
        assert response.json()["risk_level"] == "HIGH"
        assert (
            "send_money_to_receive_money"
            in response.json()["signals"]
        )
    finally:
        analyze.GemmaService = original_service


def test_analyze_fake_kyc_payment_scam():
    response_data = {
        "risk_level": "HIGH",
        "scam_type": "KYC scam",
        "signals": [
            "fake_kyc",
            "urgent_payment",
            "account_blocking_threat",
        ],
        "explanation": (
            "The message threatens account suspension and requests "
            "payment for KYC verification."
        ),
        "recommended_actions": [
            "Do not make the requested payment.",
            "Verify KYC status through the official bank application.",
        ],
    }

    class MockGemmaService:
        def analyze_text(self, text):
            assert "kyc" in text.lower()
            assert "account will be blocked" in text.lower()
            return response_data

    from app.api import analyze

    original_service = analyze.GemmaService
    analyze.GemmaService = MockGemmaService

    try:
        response = client.post(
            "/analyze/text",
            json={
                "text": (
                    "Complete KYC by paying ₹1000 now or your bank "
                    "account will be blocked."
                )
            },
        )

        assert response.status_code == 200
        assert response.json()["risk_level"] == "HIGH"
        assert "fake_kyc" in response.json()["signals"]
    finally:
        analyze.GemmaService = original_service