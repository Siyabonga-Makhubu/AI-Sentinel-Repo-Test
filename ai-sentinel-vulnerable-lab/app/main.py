from fastapi import FastAPI
from .vulnerable_routes import router

app = FastAPI(title="AI Sentinel Vulnerable Lab", docs_url=None, redoc_url=None)
app.include_router(router)
