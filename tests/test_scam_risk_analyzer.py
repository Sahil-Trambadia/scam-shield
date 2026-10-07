import pytest

from app.models.scam_analysis import ScamAnalysis
from app.services.scam_risk_analyzer import ScamRiskAnalyzer


def create_analysis(
    risk_level="HIGH",
    signals=None,
    recommended_actions=None,
):
    return ScamAnalysis(
        risk_level=risk_level,
        scam_type="payment scam",
        signals=signals or [],
        explanation="Suspicious payment-related activity.",
        recommended_actions=recommended_actions or [],
    )


def test_upi_pin_request_adds_credential_warning():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        signals=["upi_pin_request", "urgent payment"],
    )

    result = analyzer.analyze(analysis)

    assert (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    ) in result.recommended_actions


def test_upi_otp_request_adds_credential_warning():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        signals=["upi otp", "payment verification"],
    )

    result = analyzer.analyze(analysis)

    assert (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    ) in result.recommended_actions


def test_payment_pin_request_adds_credential_warning():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        signals=["payment pin request"],
    )

    result = analyzer.analyze(analysis)

    assert (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    ) in result.recommended_actions


def test_duplicate_signals_are_removed():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        signals=[
            "Urgency",
            "urgency",
            "UPI payment",
            "UPI payment",
        ],
    )

    result = analyzer.analyze(analysis)

    assert result.signals == [
        "Urgency",
        "UPI payment",
    ]


def test_duplicate_recommendations_are_removed():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        signals=["urgent payment"],
        recommended_actions=[
            "Do not respond.",
            "do not respond.",
            "Contact your bank.",
        ],
    )

    result = analyzer.analyze(analysis)

    assert result.recommended_actions == [
        "Do not respond.",
        "Contact your bank.",
    ]


def test_risk_level_is_normalized():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        risk_level="  critical  ",
    )

    result = analyzer.analyze(analysis)

    assert result.risk_level == "CRITICAL"


def test_invalid_risk_level_is_rejected():
    analyzer = ScamRiskAnalyzer()

    analysis = create_analysis(
        risk_level="UNKNOWN",
    )

    with pytest.raises(
        ValueError,
        match="Invalid risk level returned by model",
    ):
        analyzer.analyze(analysis)


def test_existing_credential_warning_is_not_duplicated():
    analyzer = ScamRiskAnalyzer()

    warning = (
        "Do not share passwords, OTPs, PINs, or other authentication "
        "credentials."
    )

    analysis = create_analysis(
        signals=["UPI PIN request"],
        recommended_actions=[warning],
    )

    result = analyzer.analyze(analysis)

    assert result.recommended_actions.count(warning) == 1