"""Discovery and construction of shipped CTF agents.

Agent modules opt in with ``@AgentRegistry.register(order=...)``.  CLI entry
points discover those modules and ask the registry to construct them, so adding
a specialist no longer requires editing each entry point.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Type


@dataclass(frozen=True)
class AgentRegistration:
    """Immutable metadata recorded by the class decorator."""

    name: str
    agent_class: Type[Any]
    order: int


class AgentRegistry:
    """Ordered registry for discoverable agent classes."""

    _registrations: Dict[str, AgentRegistration] = {}
    _discovered = False
    _discovery_packages = ("agents.specialists", "agents.support")

    @classmethod
    def register(cls, *, name: str | None = None, order: int = 100):
        """Return a class decorator that registers an agent implementation."""

        def decorator(agent_class: Type[Any]) -> Type[Any]:
            registration_name = name or agent_class.__name__
            existing = cls._registrations.get(registration_name)
            if existing and existing.agent_class is not agent_class:
                raise ValueError(f"agent registration {registration_name!r} already exists")
            cls._registrations[registration_name] = AgentRegistration(
                name=registration_name,
                agent_class=agent_class,
                order=int(order),
            )
            return agent_class

        return decorator

    @classmethod
    def discover(cls, packages: Iterable[str] | None = None) -> None:
        """Import agent modules so their registration decorators execute."""
        if packages is None and cls._discovered:
            return
        package_names = tuple(packages or cls._discovery_packages)
        for package_name in package_names:
            package = importlib.import_module(package_name)
            package_path = getattr(package, "__path__", None)
            if package_path is None:
                continue
            prefix = package.__name__ + "."
            module_names = {
                module.name
                for module in pkgutil.walk_packages(package_path, prefix)
            }
            # Some existing specialist folders intentionally omit __init__.py.
            # Include their modules without requiring a packaging rewrite.
            for root_text in package_path:
                root = Path(root_text)
                for source in root.rglob("*_agent.py"):
                    relative = source.relative_to(root).with_suffix("")
                    module_names.add(prefix + ".".join(relative.parts))
            for module_name in sorted(module_names):
                importlib.import_module(module_name)
        if packages is None:
            cls._discovered = True

    @classmethod
    def registrations(cls) -> List[AgentRegistration]:
        """Return registered classes in stable construction order."""
        return sorted(
            cls._registrations.values(),
            key=lambda item: (item.order, item.name),
        )

    @classmethod
    def create_all(cls, dependencies: Mapping[str, Any] | None = None) -> List[Any]:
        """Discover and instantiate all agents with matching named dependencies.

        Only constructor parameters explicitly present in ``dependencies`` are
        injected. Defaults remain untouched, preserving each agent's standalone
        construction behavior.
        """
        cls.discover()
        available = dict(dependencies or {})
        agents: List[Any] = []
        for registration in cls.registrations():
            parameters = inspect.signature(registration.agent_class.__init__).parameters
            kwargs = {
                key: value
                for key, value in available.items()
                if key in parameters and key != "self"
            }
            agents.append(registration.agent_class(**kwargs))
        return agents

    @classmethod
    def register_all(
        cls,
        coordinator: Any,
        dependencies: Mapping[str, Any] | None = None,
    ) -> List[Any]:
        """Construct every registered agent and attach it to a coordinator."""
        agents = cls.create_all(dependencies)
        for agent in agents:
            coordinator.register_agent(agent)
        return agents
