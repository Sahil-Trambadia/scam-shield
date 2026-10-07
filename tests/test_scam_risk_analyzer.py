import pytest

from app.models.scam_analysis import ScamAnalysis
from app.services.scam_risk_analyzer import ScamRiskAnalyzer


def create_analysis(**overrides):
    data = {
        "risk_level": "HIGH",
        "scam_type": "phishing",
        "signals": [
            "OTP request",
            "Urgency",
            "OTP request",
            "",
        ],
        "explanation": "The message requests an OTP and creates urgency.",
        "recommended_actions": [
            "Do not respond to the message.",
            "Do not respond to the message.",
        ],
    }

    data.update(overrides)

    return ScamAnalysis(**data)


def test_normalizes_risk_level_and_signals():
    analyzer = ScamRiskAnalyzer()

    result = analyzer.analyze(
        create_analysis(risk_level="high")
    )

    assert result.risk_level == "HIGH"
    assert result.signals == [
        "OTP request",
        "Urgency",
    ]


def test_adds_credential_safety_warning():
    analyzer = ScamRiskAnalyzer()

    result = analyzer.analyze(
        create_analysis()
    )

    assert (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    ) in result.recommended_actions


def test_removes_duplicate_recommendations():
    analyzer = ScamRiskAnalyzer()

    result = analyzer.analyze(
        create_analysis()
    )

    assert result.recommended_actions.count(
        "Do not respond to the message."
    ) == 1


def test_rejects_invalid_risk_level():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(risk_level="UNKNOWN")

    with pytest.raises(
        ValueError,
        match="Invalid risk level returned by model",
    ):
        analyzer.analyze(analysis)