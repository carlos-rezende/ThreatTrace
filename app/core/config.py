"""
Configuração da aplicação ThreatTrace
"""
import os
from functools import lru_cache


@lru_cache
def get_settings():
    return Settings()


class Settings:
    """Configurações da aplicação"""
    
    # URLHaus API - Obrigatório: obtenha em https://auth.abuse.ch/
    URLHAUS_AUTH_KEY: str = os.getenv("URLHAUS_AUTH_KEY", "")
    
    # GitHub API - Opcional: para módulo github (rate limits)
    GITHUB_TOKEN: str | None = os.getenv("GITHUB_TOKEN") or None
    
    # Cache
    CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", "3600"))  # 1 hora
    CACHE_MAX_SIZE: int = int(os.getenv("CACHE_MAX_SIZE", "1000"))
    
    # Rate limiting
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
    RATE_LIMIT_PERIOD: str = os.getenv("RATE_LIMIT_PERIOD", "1 minute")
    
    # Server
    PORT: int = int(os.getenv("PORT", "8090"))
    
    # API
    API_TITLE: str = "ThreatTrace API"
    API_DESCRIPTION: str = "Threat Intelligence OSINT - Análise de infraestrutura de malware"
    API_VERSION: str = "1.0.0"
