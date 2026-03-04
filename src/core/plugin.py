from abc import ABC, abstractmethod
from typing import Any, Dict


class BasePlugin(ABC):
    """Abstract base class for all plugins.

    Subclasses should override name, description, category, and version.
    """

    # Metadata to be set by subclasses
    name: str = "base"
    description: str = "Base plugin"
    category: str = "core"
    version: str = "0.0.0"

    @abstractmethod
    def init(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with configuration."""

    @abstractmethod
    def run(self, params: Dict[str, Any]) -> None:
        """Run the plugin action with params."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the plugin and perform any cleanup."""

    @abstractmethod
    def get_results(self) -> Dict[str, Any]:
        """Return a dictionary of results produced by the plugin."""

    def validate_params(self, params: Dict[str, Any], schema: Dict[str, Any]) -> None:
        """Validate params against a minimal schema.

        Currently supports a simple schema with a top-level 'required' list of keys.
        Raises ValueError if required keys are missing.
        """
        if not schema:
            return

        required = schema.get("required")
        if required:
            missing = [k for k in required if k not in params]
            if missing:
                raise ValueError(f"Missing required params: {missing}")
