from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.analyze import router as analyze_router


BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"


app = FastAPI(
    title="Scam Shield",
    description="An open-source multimodal AI assistant for detecting, explaining, and preventing online scams.",
    version="0.1.0",
)

app.include_router(analyze_router)

app.mount(
    "/static",
    StaticFiles(directory=WEB_DIR),
    name="static",
)


@app.get("/")
def home():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "scam-shield",
    }