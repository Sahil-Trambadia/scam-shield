from fastapi import APIRouter, HTTPException

from app.models.analyze_request import AnalyzeTextRequest
from app.services.gemma_service import GemmaService


router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("/text")
def analyze_text(request: AnalyzeTextRequest):
    try:
        service = GemmaService()
        return service.analyze_text(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc