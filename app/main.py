"""
ThreatTrace - Threat Intelligence OSINT Application
"""
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.datastructures import Headers
from starlette.responses import FileResponse as StarletteFileResponse
from starlette.staticfiles import NotModifiedResponse, StaticFiles as StarletteStaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.limiter import limiter
from app.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threattrace")

settings = get_settings()
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

MIME_TYPES = {
    ".css": "text/css",
    ".js": "application/javascript",
}


class StaticFilesWithMime(StarletteStaticFiles):
    def file_response(self, full_path, stat_result, scope, status_code=200):
        ext = os.path.splitext(str(full_path))[1].lower()
        media_type = MIME_TYPES.get(ext)
        response = StarletteFileResponse(
            full_path,
            status_code=status_code,
            stat_result=stat_result,
            media_type=media_type,
        )
        request_headers = Headers(scope=scope)
        if self.is_not_modified(response.headers, request_headers):
            return NotModifiedResponse(response.headers)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle da aplicação"""
    yield


app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Frontend estático (StaticFilesWithMime garante Content-Type correto em produção)
app.mount("/static", StaticFilesWithMime(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    """Página inicial - Interface web"""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api")
async def api_info():
    """Informações da API"""
    return {
        "name": "ThreatTrace",
        "description": "Threat Intelligence OSINT - Análise de infraestrutura de malware",
        "docs": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "domain": "/api/domain/{domain}",
            "url": "/api/url/{url}",
            "hash": "/api/hash/{hash}",
            "campaigns": "/api/campaigns/{domain}",
            "graph": "/api/graph/{domain}",
            "export_json": "/api/export/json",
            "export_pdf": "/api/export/pdf",
            "export_domain": "/api/export/domain/{domain}",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=True,
    )
