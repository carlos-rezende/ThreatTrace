"""
GitHub OSINT Module - Search for target in public repos
Requires GITHUB_TOKEN for higher rate limits.
"""
import httpx
from app.modules.base import ThreatModule, ModuleResult


class GitHubModule(ThreatModule):
    """Searches GitHub for references to target domain"""
    name = "github"
    description = "GitHub code search for domain references"

    def __init__(self, token: str | None = None):
        self.token = token

    async def run(self, target: str) -> ModuleResult:
        """Search GitHub for target domain"""
        domain = target.strip().lower()
        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(
                    "https://api.github.com/search/code",
                    params={"q": f'"{domain}"', "per_page": 10},
                    headers=headers,
                )
                if r.status_code == 403:
                    return ModuleResult(
                        source="github.com",
                        module_name=self.name,
                        target=target,
                        data={"error": "Rate limited. Add GITHUB_TOKEN for higher limits.", "results": []},
                        meta={"success": False},
                    )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            return ModuleResult(
                source="github.com",
                module_name=self.name,
                target=target,
                data={"error": str(e), "results": []},
                meta={"success": False},
            )

        items = data.get("items", [])[:10]
        results = [
            {
                "repository": i.get("repository", {}).get("full_name"),
                "path": i.get("path"),
                "html_url": i.get("html_url"),
            }
            for i in items
        ]

        return ModuleResult(
            source="github.com",
            module_name=self.name,
            target=target,
            data={"results": results, "total_count": data.get("total_count", 0)},
            meta={"success": True},
        )
