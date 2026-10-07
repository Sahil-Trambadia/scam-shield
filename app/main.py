from fastapi import FastAPI

app = FastAPI(
    title="Scam Shield",
    description="An open-source multimodal AI assistant for detecting, explaining, and preventing online scams.",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "scam-shield",
    }