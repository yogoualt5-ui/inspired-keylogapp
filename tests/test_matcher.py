from scanner.matcher import _version_in_range


def test_version_less_than_matches():
    assert _version_in_range("6.4.2", "<6.4.3") is True


def test_version_less_than_not_match():
    assert _version_in_range("6.4.3", "<6.4.3") is False


def test_unknown_version_is_possible():
    assert _version_in_range("unknown", "<9.9.9") is True
