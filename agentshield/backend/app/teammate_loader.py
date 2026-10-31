from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import re
import sys
import threading
import types
from pathlib import Path
from typing import Any, Callable

from .config import Settings


_P1_ALIAS = "agentshield_p1"
_P2_ALIAS = "agentshield_offline"

_LOCK = threading.RLock()
_ALIAS_ROOTS: dict[str, Path] = {}
_REWRITERS: dict[str, Callable[[str], str]] = {}
_CACHE: dict[str, dict[str, Any]] = {}
_FINDER_INSTALLED = False


def _rewrite_p1(source: str) -> str:
    source = re.sub(
        r"(?m)^(\s*)from\s+core(?=[\s.])",
        r"\1from agentshield_p1.core",
        source,
    )
    return re.sub(
        r"(?m)^(\s*)import\s+core(?=[\s,.]|$)",
        r"\1import agentshield_p1.core",
        source,
    )


def _rewrite_p2(source: str) -> str:
    source = re.sub(
        r"(?m)^(\s*)from\s+app(?=[\s.])",
        r"\1from agentshield_offline.app",
        source,
    )
    return re.sub(
        r"(?m)^(\s*)import\s+app(?=[\s,.]|$)",
        r"\1import agentshield_offline.app",
        source,
    )


class _RewritingSourceLoader(importlib.machinery.SourceFileLoader):
    def __init__(
        self, fullname: str, path: str, rewriter: Callable[[str], str]
    ) -> None:
        super().__init__(fullname, path)
        self._rewriter = rewriter

    def get_source(self, fullname: str) -> str:
        source = importlib.util.decode_source(self.get_data(self.path))
        return self._rewriter(source)

    def get_code(self, fullname: str) -> types.CodeType:
        return compile(
            self.get_source(fullname),
            self.path,
            "exec",
            dont_inherit=True,
        )


class _AliasFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path: Any = None, target: Any = None):
        for alias, root in list(_ALIAS_ROOTS.items()):
            if fullname == alias or not fullname.startswith(f"{alias}."):
                continue
            relative = fullname[len(alias) + 1 :]
            if not relative:
                return None
            candidate = root.joinpath(*relative.split("."))
            rewriter = _REWRITERS[alias]
            if candidate.is_dir():
                init_file = candidate / "__init__.py"
                if init_file.is_file():
                    loader = _RewritingSourceLoader(
                        fullname, str(init_file), rewriter
                    )
                    return importlib.util.spec_from_file_location(
                        fullname,
                        str(init_file),
                        loader=loader,
                        submodule_search_locations=[str(candidate)],
                    )
                return importlib.util.spec_from_file_location(
                    fullname,
                    None,
                    loader=None,
                    submodule_search_locations=[str(candidate)],
                )
            module_file = candidate.with_suffix(".py")
            if module_file.is_file():
                loader = _RewritingSourceLoader(
                    fullname, str(module_file), rewriter
                )
                return importlib.util.spec_from_file_location(
                    fullname,
                    str(module_file),
                    loader=loader,
                )
            return None
        return None

    def invalidate_caches(self) -> None:
        return None


def _install_finder() -> None:
    global _FINDER_INSTALLED
    if _FINDER_INSTALLED:
        return
    sys.meta_path.insert(0, _AliasFinder())
    _FINDER_INSTALLED = True


def _install_alias(
    alias: str,
    root: Path,
    rewriter: Callable[[str], str],
) -> None:
    _install_finder()
    _ALIAS_ROOTS[alias] = root
    _REWRITERS[alias] = rewriter
    module = sys.modules.get(alias)
    if module is None:
        module = types.ModuleType(alias)
        module.__path__ = [str(root)]
        module.__package__ = alias
        module.__file__ = None
        module.__spec__ = importlib.machinery.ModuleSpec(
            alias, loader=None, is_package=True
        )
        module.__spec__.submodule_search_locations = [str(root)]
        sys.modules[alias] = module


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_root(
    configured: str | None,
    default: Path,
    *,
    required_child: str,
) -> Path:
    root = Path(configured).expanduser() if configured else default
    if not root.is_absolute():
        root = Path.cwd() / root
    root = root.resolve()
    if not (root / required_child).is_dir():
        raise FileNotFoundError(
            f"teammate module root '{root}' does not contain '{required_child}'"
        )
    return root


def p1_root(settings: Settings | None = None) -> Path:
    default = (
        _repo_root()
        / "teammate-submissions"
        / "mu_part"
        / "penetration-prevention--main"
    )
    configured = settings.p1_module_path if settings else None
    return _resolve_root(configured, default, required_child="core")


def p2_root(settings: Settings | None = None) -> Path:
    default = (
        _repo_root()
        / "teammate-submissions"
        / "mu_part"
        / "agentshield-offline"
    )
    configured = settings.p2_module_path if settings else None
    return _resolve_root(configured, default, required_child="app")


def load_p1(settings: Settings | None = None) -> dict[str, Any]:
    with _LOCK:
        cached = _CACHE.get("p1")
        if cached is not None:
            return cached
        root = p1_root(settings)
        _install_alias(_P1_ALIAS, root, _rewrite_p1)
        modules = {
            "config": importlib.import_module("agentshield_p1.core.config"),
            "schemas": importlib.import_module("agentshield_p1.core.schemas"),
            "security_engine": importlib.import_module(
                "agentshield_p1.core.security_engine"
            ),
        }
        _CACHE["p1"] = modules
        return modules


def load_p2(settings: Settings | None = None) -> dict[str, Any]:
    with _LOCK:
        cached = _CACHE.get("p2")
        if cached is not None:
            return cached
        root = p2_root(settings)
        _install_alias(_P2_ALIAS, root, _rewrite_p2)
        modules = {
            "root": root,
            "configuration": importlib.import_module(
                "agentshield_offline.app.core.configuration"
            ),
            "contracts": importlib.import_module(
                "agentshield_offline.app.core.contracts"
            ),
            "decisions": importlib.import_module(
                "agentshield_offline.app.core.decisions"
            ),
            "ports": importlib.import_module(
                "agentshield_offline.app.integrations.ports"
            ),
            "local_content_inspector": importlib.import_module(
                "agentshield_offline.app.integrations.local_content_inspector"
            ),
            "documents": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.documents.gateway"
            ),
            "document_inspector": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.documents.document_inspector"
            ),
            "document_parser": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.documents.parser"
            ),
            "malware_scanner": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.documents.malware_scanner"
            ),
            "quarantine": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.documents.quarantine"
            ),
            "filesystem": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.local_files.filesystem_gateway"
            ),
            "directory_scopes": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.local_files.directory_scopes"
            ),
            "system_files": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.system_files.gateway"
            ),
            "environment": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.environment.gateway"
            ),
            "environment_policy": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.environment.environment_policy"
            ),
            "environment_guard": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.environment.environment_guard"
            ),
            "secret_broker": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.environment.secret_broker"
            ),
            "secret_provider": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.environment.secret_provider"
            ),
            "terminal": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.terminal.gateway"
            ),
            "command_policy": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.terminal.command_policy"
            ),
            "execution_worker": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.terminal.execution_worker"
            ),
            "terminal_output_inspector": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.terminal.output_inspector"
            ),
            "sandbox_manager": importlib.import_module(
                "agentshield_offline.app.capabilities.offline.terminal.sandbox_manager"
            ),
        }
        _CACHE["p2"] = modules
        return modules


def loaded_roots() -> dict[str, str]:
    return {alias: str(root) for alias, root in _ALIAS_ROOTS.items()}
