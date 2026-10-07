import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    app_name: str = "Scam Shield"
    app_version: str = "0.1.0"
    gemini_api_key: str | None = os.getenv("GEMINI_API_KEY")
    gemma_model: str = os.getenv(
        "GEMMA_MODEL",
        "gemma-4-26b-a4b-it",
    )


settings = Settings()