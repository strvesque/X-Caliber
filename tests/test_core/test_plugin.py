import pytest


def test_plugin_interface_is_abstract():
    # Import inside test to ensure module import works
    from src.core.plugin import BasePlugin

    # BasePlugin should be abstract and not instantiable
    with pytest.raises(TypeError):
        BasePlugin()


def test_validate_params_helper_raises_on_missing_keys():
    from src.core.plugin import BasePlugin

    # Create a minimal concrete subclass for testing
    class DummyPlugin(BasePlugin):
        name = "dummy"
        description = "A dummy plugin"
        category = "test"
        version = "0.0.1"

        def init(self, config):
            pass

        def run(self, params):
            pass

        def stop(self):
            pass

        def get_results(self) -> dict:
            return {}

    plugin = DummyPlugin()

    # Schema requires 'a' and 'b'
    schema = {"required": ["a", "b"]}

    # Missing both keys should raise ValueError
    with pytest.raises(ValueError):
        plugin.validate_params({}, schema)

    # Missing one key should also raise
    with pytest.raises(ValueError):
        plugin.validate_params({"a": 1}, schema)


def test_minimal_concrete_plugin_can_be_instantiated_and_run():
    from src.core.plugin import BasePlugin

    class EchoPlugin(BasePlugin):
        name = "echo"
        description = "Echo plugin"
        category = "utility"
        version = "0.1"

        def init(self, config):
            self.config = config

        def run(self, params):
            self._results = {"echo": params}

        def stop(self):
            self._stopped = True

        def get_results(self) -> dict:
            return getattr(self, "_results", {})

    p = EchoPlugin()
    p.init({"foo": "bar"})
    p.run({"msg": "hello"})
    assert p.get_results() == {"echo": {"msg": "hello"}}
