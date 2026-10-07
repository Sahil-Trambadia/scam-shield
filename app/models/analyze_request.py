from pydantic import BaseModel, Field


class AnalyzeTextRequest(BaseModel):
    text: str = Field(
        min_length=1,
        description="Text message to analyze for potential scam indicators.",
    )