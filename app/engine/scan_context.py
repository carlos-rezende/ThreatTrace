"""
Scan context - holds state during investigation
"""
from dataclasses import dataclass, field
from typing import Any
from app.modules.base import ModuleResult


@dataclass
class ScanContext:
    """Context for a single investigation scan"""
    target: str
    module_results: dict[str, ModuleResult] = field(default_factory=dict)
    aggregated: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add_result(self, module_name: str, result: ModuleResult):
        self.module_results[module_name] = result

    def add_error(self, msg: str):
        self.errors.append(msg)
