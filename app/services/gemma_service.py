import base64

from google import genai

from app.config import settings
from app.models.scam_analysis import ScamAnalysis
from app.services.scam_risk_analyzer import ScamRiskAnalyzer
from app.services.url_analyzer import URLAnalyzer


class GemmaService:
    """Service responsible for communicating with the Gemma model."""

    def __init__(self) -> None:
        if not settings.gemini_api_key:
            raise ValueError("GEMINI_API_KEY is not configured.")

        self.client = genai.Client(api_key=settings.gemini_api_key)
        self.model = settings.gemma_model
        self.risk_analyzer = ScamRiskAnalyzer()
        self.url_analyzer = URLAnalyzer()

    def analyze_text(self, text: str) -> ScamAnalysis:
        """Analyze suspicious text using Gemma and return structured results."""

        urls = self.url_analyzer.extract_urls(text)
        url_signals = self.url_analyzer.analyze(text)

        if urls:
            url_evidence = "\n".join(
                f"- URL: {url}"
                for url in urls
            )
        else:
            url_evidence = "- No URLs detected."

        if url_signals:
            url_signal_text = "\n".join(
                f"- {signal}"
                for signal in url_signals
            )
        else:
            url_signal_text = "- No suspicious URL characteristics detected."

        prompt = f"""
You are Scam Shield, an AI assistant focused on detecting and explaining
potential online scams, with particular attention to common Indian scam
scenarios.

Analyze the following message.

Return a structured scam analysis containing:
- risk_level: LOW, MEDIUM, HIGH, or CRITICAL
- scam_type: the most likely scam category
- signals: specific suspicious signals found
- explanation: why the message may be suspicious
- recommended_actions: safe actions the user should take

Pay particular attention to:
- UPI payment requests
- requests for UPI PINs, OTPs, passwords, or other credentials
- requests to send money to receive money
- suspicious QR-code or payment instructions
- fake refunds or refund verification
- fake KYC or account verification requests
- urgent payment demands
- suspicious payment links
- impersonation of banks, payment providers, merchants, or government services
- claims that an account or service will be blocked unless payment is made
- suspicious URLs and links

For URL analysis:
- Treat locally detected URL characteristics as evidence, not proof of fraud.
- Do not claim a URL is malicious solely because it uses HTTP,
  a URL shortener, an IP address, multiple subdomains, or unusual URL
  formatting.
- Consider the surrounding message and context before assigning risk.
- Pay attention to URLs associated with payment, UPI, refunds, KYC,
  verification, account access, OTPs, PINs, or credential requests.
- Never attempt to visit, open, or access a URL.
- Do not invent information about the destination of a URL.

Locally extracted URLs:
{url_evidence}

Locally detected URL characteristics:
{url_signal_text}

For Indian payment scenarios, do not assume that mentioning UPI,
a bank, a payment provider, or a QR code is automatically fraudulent.
Assess the surrounding context and identify the specific suspicious behavior.

Do not claim certainty that something is a scam.
Do not request or expose passwords, OTPs, PINs, UPI PINs, or other
sensitive credentials.

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

        analysis = ScamAnalysis.model_validate_json(response.text)
        return self.risk_analyzer.analyze(analysis)

    def analyze_image(
        self,
        image_base64: str,
        mime_type: str,
    ) -> ScamAnalysis:
        """Analyze an image using Gemma and return structured results."""

        image_bytes = base64.b64decode(image_base64)

        prompt = """
You are Scam Shield, an AI assistant focused on detecting and explaining
potential online scams, with particular attention to common Indian scam
scenarios.

Analyze the provided image for potential scam indicators.

Look for observable evidence such as:
- urgency or pressure tactics
- requests for OTPs, passwords, PINs, or other credentials
- requests for UPI PINs or payment authentication
- suspicious payment requests
- requests to send money to receive money
- suspicious QR-code or payment instructions
- fake refunds or refund verification
- fake KYC or account verification
- impersonation of banks, payment providers, merchants, government agencies,
  or individuals
- fake delivery or account notifications
- fake prizes or rewards
- investment or job scams
- suspicious links, phone numbers, or payment instructions
- threats involving account blocking or service suspension

For Indian payment scenarios, do not assume that mentioning UPI,
a bank, a payment provider, or a QR code is automatically fraudulent.
Assess the surrounding context and identify the specific suspicious behavior.

Focus on observable evidence in the image and distinguish visible evidence
from your interpretation.

Return a structured scam analysis containing:
- risk_level: LOW, MEDIUM, HIGH, or CRITICAL
- scam_type: the most likely scam category
- signals: specific suspicious signals found
- explanation: why the content may be suspicious
- recommended_actions: safe actions the user should take

Do not claim certainty that something is a scam.
Do not request or expose passwords, OTPs, PINs, UPI PINs, or other
sensitive credentials.
"""

        response = self.client.models.generate_content(
            model=self.model,
            contents=[
                prompt,
                {
                    "data": image_bytes,
                    "mime_type": mime_type,
                },
            ],
            config={
                "response_mime_type": "application/json",
                "response_schema": ScamAnalysis,
            },
        )

        analysis = ScamAnalysis.model_validate_json(response.text)
        return self.risk_analyzer.analyze(analysis)