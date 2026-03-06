import pytest

from src.ctf.flag_finder import FlagFinder  # type: ignore


@pytest.fixture()
def finder():
    return FlagFinder()


def test_find_basic_flag_patterns(finder):
    txt = "here is a flag: flag{easy-peasy} and another CTF{Harder}"
    res = finder.find_in_text(txt)
    flags = [r["flag"] for r in res]
    assert "flag{easy-peasy}" in flags
    assert "CTF{Harder}" in flags


@pytest.mark.parametrize("sample", [
    "picoCTF{abc123}",
    "HTB{this_is_a_flag}",
    "custom{0123456789abcdef0123456789abcdef}"
])
def test_various_patterns_match(finder, sample):
    res = finder.find_in_text("prefix " + sample + " suffix")
    assert any(r["flag"] == sample for r in res)


def test_case_insensitive_matching(finder):
    txt = "Flag{MiXeD} cTf{lower}"
    res = finder.find_in_text(txt)
    flags = [r["flag"] for r in res]
    # original casing is preserved in match.group(0)
    assert any(f.lower().startswith("flag{") for f in flags)
    assert any(f.lower().startswith("ctf{") for f in flags)


def test_context_and_position(finder):
    txt = "A" * 10 + "flag{ctx-example}" + "B" * 30
    res = finder.find_in_text(txt)
    assert len(res) == 1
    r = res[0]
    assert r["position"] == 10
    # context should include some A's before and B's after
    assert "A" in r["context"]
    assert "B" in r["context"]


def test_find_in_bytes_binary_file(finder, tmp_path):
    # Create a binary file with embedded flag bytes
    data = b"\x00\x01binaryFLAG" + b"flag{bin-flag}" + b"\xff\xfe"
    p = tmp_path / "bin.dat"
    p.write_bytes(data)

    res = finder.find_in_file(str(p))
    assert any(r["flag"] == "flag{bin-flag}" for r in res)


def test_find_in_file_utf8(tmp_path, finder):
    p = tmp_path / "text.txt"
    p.write_text("some text picoCTF{unicode-✓} end", encoding="utf-8")
    res = finder.find_in_file(str(p))
    assert any(r["flag"].lower().startswith("picoctf{") for r in res)


def test_duplicate_detection(finder):
    # Same flag occurs twice but at same position via overlapping regex runs
    txt = "flag{dup} and flag{dup}"
    res = finder.find_in_text(txt)
    flags = [ (r["flag"], r["position"]) for r in res ]
    # both occurrences should be reported (different positions)
    assert len(flags) >= 2


def test_no_crash_on_missing_file(finder):
    res = finder.find_in_file("/path/does/not/exist.flag")
    assert res == []
