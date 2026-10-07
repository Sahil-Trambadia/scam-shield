import base64

from fastapi import APIRouter, HTTPException

from app.models.analyze_request import AnalyzeTextRequest
from app.models.image_analysis_request import ImageAnalysisRequest
from app.services.gemma_service import GemmaService


router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("/text")
def analyze_text(request: AnalyzeTextRequest):
    try:
        service = GemmaService()
        return service.analyze_text(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/image")
def analyze_image(request: ImageAnalysisRequest):
    try:
        base64.b64decode(request.image_base64, validate=True)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid base64 image data.",
        ) from exc

    try:
        service = GemmaService()
        return service.analyze_image(
            image_base64=request.image_base64,
            mime_type=request.mime_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc