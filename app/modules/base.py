"""
Base class for Threat Intelligence modules (SpiderFoot-style)
"""
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class ModuleResult(BaseModel):
    """Structured intelligence result from a module"""
    source: str
    module_name: str
    target: str
    data: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)


class ThreatModule(ABC):
    """
    Base class for OSINT threat intelligence modules.
    Each module implements run() to collect intelligence on a target.
    """
    name: str = "base"
    description: str = "Base module"

    @abstractmethod
    async def run(self, target: str) -> ModuleResult:
        """Execute module against target. Target can be domain, URL, or IP."""
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"
