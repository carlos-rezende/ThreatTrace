"""
Passive DNS Module - Placeholder for passive DNS lookups
Requires API key (SecurityTrails, VirusTotal, etc.) for production use.
"""
from app.modules.base import ThreatModule, ModuleResult


class PassiveDNSModule(ThreatModule):
    """Passive DNS lookups - stub for SecurityTrails/VirusTotal integration"""
    name = "passive_dns"
    description = "Passive DNS resolution history"

    async def run(self, target: str) -> ModuleResult:
        """Stub - returns empty. Add API key for SecurityTrails/VT to enable."""
        return ModuleResult(
            source="passive_dns",
            module_name=self.name,
            target=target,
            data={
                "resolutions": [],
                "message": "Configure PASSIVE_DNS_API_KEY for SecurityTrails/VirusTotal",
            },
            meta={"success": False, "enabled": False},
        )
