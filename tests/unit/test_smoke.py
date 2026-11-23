def test_package_importable():
    import agent_proxy
    assert agent_proxy.__version__ == "0.1.0"
