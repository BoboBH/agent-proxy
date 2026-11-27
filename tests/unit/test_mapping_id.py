from app.services.mapping_id import LENGTH, MAPPING_ID_RE, new_mapping_id


def test_shape():
    for _ in range(50):
        mid = new_mapping_id()
        assert len(mid) == LENGTH
        assert MAPPING_ID_RE.match(mid)


def test_random_enough():
    assert len({new_mapping_id() for _ in range(200)}) > 190


def test_re_rejects_trailing_newline():
    mid = new_mapping_id()
    assert MAPPING_ID_RE.match(mid)
    assert not MAPPING_ID_RE.match(mid + "\n")
