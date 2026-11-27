def test_package_importable():
    import app
    assert app.__version__ == "0.1.0"
