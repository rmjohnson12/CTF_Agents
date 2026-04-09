from core.utils.flag_utils import extract_flags, find_first_flag

def test_extract_flags_basic():
    text = "Here is a flag: CTF{basic_flag_123}"
    assert extract_flags(text) == ["CTF{basic_flag_123}"]

def test_extract_flags_htb():
    text = "The flag is HTB{htb_style_flag_01}"
    assert extract_flags(text) == ["HTB{htb_style_flag_01}"]

def test_extract_flags_multiple():
    text = "First CTF{one} and then HTB{two} and maybe flag{three}"
    assert extract_flags(text) == ["CTF{one}", "HTB{two}", "flag{three}"]

def test_extract_flags_complex():
    text = "A complex one: HTB{f!@#$%^&*()+=|?><}"
    assert extract_flags(text) == ["HTB{f!@#$%^&*()+=|?><}"]

def test_find_first_flag():
    text = "Multiple here: CTF{first} HTB{second}"
    assert find_first_flag(text) == "CTF{first}"

def test_no_flags():
    text = "No flags in this string."
    assert extract_flags(text) == []
    assert find_first_flag(text) is None
