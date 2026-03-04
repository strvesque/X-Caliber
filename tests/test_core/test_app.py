def test_app_imports_without_error():
    # Import src/main.py by path to avoid package import requirements
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'main.py'
    spec = importlib.util.spec_from_file_location('pentest_main', str(p))
    assert spec is not None, 'Could not load spec for src/main.py'
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    assert loader is not None, 'No loader available for spec'
    loader.exec_module(module)
    assert hasattr(module, 'main')


if __name__ == '__main__':
    test_app_imports_without_error()
