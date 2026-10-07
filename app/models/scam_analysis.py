from pydantic import BaseModel, Field


class ScamAnalysis(BaseModel):
    risk_level: str = Field(
        description="Overall scam risk: LOW, MEDIUM, HIGH, or CRITICAL."
    )
    scam_type: str = Field(
        description="Most likely scam category."
    )
    signals: list[str] = Field(
        description="Specific suspicious signals found in the content."
    )
    explanation: str = Field(
        description="Clear explanation of why the content may be suspicious."
    )
    recommended_actions: list[str] = Field(
        description="Safe actions the user should take."
    )