"""
Module runner - executes OSINT modules
"""
import asyncio
from app.modules.base import ThreatModule, ModuleResult
from app.engine.scan_context import ScanContext


class ModuleRunner:
    """Runs threat intelligence modules against a target"""

    def __init__(self, modules: list[ThreatModule]):
        self.modules = {m.name: m for m in modules}

    async def run_module(self, name: str, target: str) -> ModuleResult | None:
        """Run single module"""
        mod = self.modules.get(name)
        if mod is None:
            return None
        return await mod.run(target)

    async def run_all(self, target: str, module_names: list[str] | None = None) -> ScanContext:
        """Run modules (or subset) against target"""
        ctx = ScanContext(target=target)
        names = module_names or list(self.modules.keys())

        async def run_one(name: str):
            mod = self.modules.get(name)
            if mod:
                try:
                    result = await mod.run(target)
                    ctx.add_result(name, result)
                except Exception as e:
                    ctx.add_error(f"{name}: {e}")

        await asyncio.gather(*[run_one(n) for n in names if n in self.modules])
        return ctx
