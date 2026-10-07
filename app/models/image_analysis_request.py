from typing import Literal

from pydantic import BaseModel, Field


class ImageAnalysisRequest(BaseModel):
    image_base64: str = Field(
        min_length=1,
        description="Base64-encoded image to analyze for potential scam indicators.",
    )
    mime_type: Literal["image/jpeg", "image/png", "image/webp"] = Field(
        description="MIME type of the image.",
    )