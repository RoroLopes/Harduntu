from Harduntu.checks.ssh import parse_sshd_config_text, update_sshd_config_entry


def test_parse_sshd_config_text_strips_comments():
    text = """# comment line
PermitRootLogin no
PasswordAuthentication yes # inline comment
# another comment
"""
    entries = parse_sshd_config_text(text, "/tmp/sshd_config")

    assert len(entries) == 2
    assert entries[0].directive == "PermitRootLogin"
    assert entries[0].value == "no"
    assert entries[1].directive == "PasswordAuthentication"
    assert entries[1].value == "yes"


def test_update_sshd_config_entry_modifies_last_directive():
    entries = []
    entries = update_sshd_config_entry(entries, "PermitRootLogin", "no", "/tmp/sshd_config")

    assert entries[-1].directive == "PermitRootLogin"
    assert entries[-1].value == "no"
