"""
Module loader - discovers and loads OSINT threat modules
"""
from typing import Type
from app.modules.base import ThreatModule
from app.modules.urlhaus_module import URLHausModule
from app.modules.crtsh_module import CrtshModule
from app.modules.passive_dns_module import PassiveDNSModule
from app.modules.github_module import GitHubModule


_REGISTRY: dict[str, Type[ThreatModule]] = {
    "urlhaus": URLHausModule,
    "crtsh": CrtshModule,
    "passive_dns": PassiveDNSModule,
    "github": GitHubModule,
}


def get_available_modules() -> list[str]:
    """Return list of available module names"""
    return list(_REGISTRY.keys())


def load_module(name: str, **kwargs) -> ThreatModule | None:
    """Load module by name with optional init kwargs"""
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    try:
        return cls(**kwargs)
    except TypeError:
        return cls()


def load_all_modules(urlhaus_key: str = "", github_token: str | None = None) -> list[ThreatModule]:
    """Load all modules with config"""
    modules = []
    if urlhaus_key:
        modules.append(URLHausModule(urlhaus_key))
    modules.append(CrtshModule())
    modules.append(PassiveDNSModule())
    modules.append(GitHubModule(github_token))
    return modules
