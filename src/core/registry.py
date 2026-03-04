"""Plugin discovery and registration system."""
import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Type, List, Dict, Any

from src.core.plugin import BasePlugin


class PluginRegistry:
    """Manages plugin discovery and registration."""
    
    def __init__(self):
        self._plugins: Dict[str, Type[BasePlugin]] = {}
    
    def discover_plugins(self, plugins_dir: str = "src/plugins") -> List[Type[BasePlugin]]:
        """Discover all BasePlugin subclasses in plugins directory.
        
        Args:
            plugins_dir: Directory to scan for plugins
            
        Returns:
            List of discovered plugin classes
        """
        discovered = []
        plugins_path = Path(plugins_dir)
        
        if not plugins_path.exists():
            return discovered
        
        # Scan recursively for Python files
        for py_file in plugins_path.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue  # Skip __init__.py and private files
            
            # Convert path to module name
            relative_path = py_file
            module_name = str(relative_path.with_suffix("")).replace("/", ".").replace("\\", ".")
            
            try:
                # Import the module
                if module_name in sys.modules:
                    module = sys.modules[module_name]
                else:
                    module = importlib.import_module(module_name)
                
                # Find all BasePlugin subclasses
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if obj is BasePlugin:
                        continue  # Skip the base class itself
                    
                    if issubclass(obj, BasePlugin) and obj.__module__ == module_name:
                        discovered.append(obj)
                        self._plugins[obj.name] = obj
                        
            except Exception as e:
                # Skip files that can't be imported
                print(f"Warning: Could not import {module_name}: {e}")
                continue
        
        return discovered
    
    def get_plugin(self, name: str) -> Type[BasePlugin] | None:
        """Get plugin class by name."""
        return self._plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins with metadata."""
        return [
            {
                "name": plugin.name,
                "category": plugin.category,
                "description": plugin.description,
                "version": getattr(plugin, "version", "unknown")
            }
            for plugin in self._plugins.values()
        ]


# Global registry instance
_registry = PluginRegistry()


def get_registry() -> PluginRegistry:
    """Get the global plugin registry."""
    return _registry
