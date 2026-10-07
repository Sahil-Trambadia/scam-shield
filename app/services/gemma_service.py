from google import genai

from app.config import settings
from app.models.scam_analysis import ScamAnalysis


class GemmaService:
    """Service responsible for communicating with the Gemma model."""

    def __init__(self) -> None:
        if not settings.gemini_api_key:
            raise ValueError("GEMINI_API_KEY is not configured.")

        self.client = genai.Client(api_key=settings.gemini_api_key)
        self.model = settings.gemma_model

    def analyze_text(self, text: str) -> ScamAnalysis:
        """Analyze suspicious text using Gemma and return structured results."""

        prompt = f"""
You are Scam Shield, an AI assistant focused on detecting and explaining
potential online scams.

Analyze the following message.

Return a structured scam analysis containing:
- risk_level: LOW, MEDIUM, HIGH, or CRITICAL
- scam_type: the most likely scam category
- signals: specific suspicious signals found
- explanation: why the message may be suspicious
- recommended_actions: safe actions the user should take

Do not claim certainty that something is a scam.
Do not request or expose passwords, OTPs, PINs, or other sensitive credentials.

Message to analyze:
{text}
"""

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "response_schema": ScamAnalysis,
            },
        )

        return ScamAnalysis.model_validate_json(response.text)