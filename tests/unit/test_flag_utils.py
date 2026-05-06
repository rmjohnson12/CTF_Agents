from core.utils.flag_utils import extract_flags, find_first_flag

def test_extract_flags_basic():
    text = "Here is a flag: CTF{basic_flag_123}"
    assert extract_flags(text) == ["CTF{basic_flag_123}"]

def test_extract_flags_htb():
    text = "The flag is HTB{htb_style_flag_01}"
    assert extract_flags(text) == ["HTB{htb_style_flag_01}"]

def test_extract_flags_multiple():
    text = "First CTF{flag_one} and then HTB{flag_two} and maybe flag{three_is_long} and NCL SKY-ABCD-1234"
    assert extract_flags(text) == ["CTF{flag_one}", "HTB{flag_two}", "flag{three_is_long}", "SKY-ABCD-1234"]

def test_extract_flags_ncl():
    text = "Found it: SKY-QIZK-8026"
    assert extract_flags(text) == ["SKY-QIZK-8026"]

def test_extract_flags_complex():
    text = "A complex one: HTB{f!@#$%^&*()+=|?><}"
    assert extract_flags(text) == ["HTB{f!@#$%^&*()+=|?><}"]

def test_find_first_flag():
    text = "Multiple here: CTF{first_flag} HTB{second_flag}"
    assert find_first_flag(text) == "CTF{first_flag}"

def test_no_flags():
    text = "No flags in this string."
    assert extract_flags(text) == []
    assert find_first_flag(text) is None

def test_ignores_single_letter_brace_fragments():
    text = 'input(f"\\n{prompt_text}").strip()'
    assert extract_flags(text) == []
