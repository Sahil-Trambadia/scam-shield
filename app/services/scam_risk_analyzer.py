from app.models.scam_analysis import ScamAnalysis


VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

CREDENTIAL_SIGNALS = {
    "otp",
    "otp request",
    "upi otp",
    "payment otp",
    "password",
    "password request",
    "pin",
    "pin request",
    "upi pin",
    "upi pin request",
    "payment pin",
    "credential request",
    "banking credential",
}


class ScamRiskAnalyzer:
    """Validates and normalizes Gemma's scam analysis."""

    def analyze(self, analysis: ScamAnalysis) -> ScamAnalysis:
        """Return a normalized and safety-checked scam analysis."""

        risk_level = analysis.risk_level.strip().upper()

        if risk_level not in VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk level returned by model: {analysis.risk_level}"
            )

        signals = self._normalize_signals(analysis.signals)
        recommended_actions = self._normalize_recommendations(
            analysis.recommended_actions
        )

        if self._contains_credential_request(signals):
            credential_warning = (
                "Do not share passwords, OTPs, PINs, or other authentication "
                "credentials."
            )

            if credential_warning not in recommended_actions:
                recommended_actions.insert(0, credential_warning)

        return analysis.model_copy(
            update={
                "risk_level": risk_level,
                "signals": signals,
                "recommended_actions": recommended_actions,
            }
        )

    @staticmethod
    def _normalize_signals(signals: list[str]) -> list[str]:
        """Clean signals and remove duplicates while preserving order."""

        normalized = []
        seen = set()

        for signal in signals:
            cleaned = signal.strip()

            if not cleaned:
                continue

            key = cleaned.casefold()

            if key not in seen:
                seen.add(key)
                normalized.append(cleaned)

        return normalized

    @staticmethod
    def _normalize_recommendations(
        recommendations: list[str],
    ) -> list[str]:
        """Clean recommendations and remove duplicates while preserving order."""

        normalized = []
        seen = set()

        for recommendation in recommendations:
            cleaned = recommendation.strip()

            if not cleaned:
                continue

            key = cleaned.casefold()

            if key not in seen:
                seen.add(key)
                normalized.append(cleaned)

        return normalized

    @staticmethod
    def _contains_credential_request(signals: list[str]) -> bool:
        """Check whether signals indicate a request for sensitive credentials."""

        for signal in signals:
            normalized = signal.casefold()

            if any(
                credential_signal in normalized
                for credential_signal in CREDENTIAL_SIGNALS
            ):
                return True

        return False