import base64

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

    def analyze_image(
        self,
        image_base64: str,
        mime_type: str,
    ) -> ScamAnalysis:
        """Analyze a suspicious image using Gemma's multimodal capabilities."""

        try:
            image_bytes = base64.b64decode(image_base64, validate=True)
        except ValueError as exc:
            raise ValueError("Invalid base64 image data.") from exc

        prompt = """
You are Scam Shield, an AI assistant focused on detecting and explaining
potential online scams.

Analyze the provided image for potential scam indicators.

Look for observable evidence such as:
- urgency or pressure tactics
- requests for OTPs, passwords, PINs, or other credentials
- suspicious payment requests
- impersonation of banks, companies, government agencies, or individuals
- fake delivery or account notifications
- fake prizes or rewards
- investment or job scams
- suspicious links, phone numbers, or payment instructions

Return a structured scam analysis containing:
- risk_level: LOW, MEDIUM, HIGH, or CRITICAL
- scam_type: the most likely scam category
- signals: specific suspicious signals visible in the image
- explanation: why the content may be suspicious
- recommended_actions: safe actions the user should take

Do not claim certainty that the content is a scam.
Do not request or expose passwords, OTPs, PINs, or other sensitive credentials.

Focus on observable evidence in the image and distinguish visible evidence
from your interpretation.
"""

        image_part = genai.types.Part.from_bytes(
            data=image_bytes,
            mime_type=mime_type,
        )

        response = self.client.models.generate_content(
            model=self.model,
            contents=[prompt, image_part],
            config={
                "response_mime_type": "application/json",
                "response_schema": ScamAnalysis,
            },
        )

        return ScamAnalysis.model_validate_json(response.text)