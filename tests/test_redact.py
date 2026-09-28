from core.redact import redact_line, redact_lines


def test_redact_auth_login_command():
    assert redact_line("AUTH LOGIN") == "[REDACTED]"


def test_redact_auth_plain_with_inline_creds():
    assert redact_line("AUTH PLAIN AGxhYnVzZXIAbGFicGFzcw==") == "[REDACTED]"


def test_redact_user_command():
    assert redact_line("USER labuser") == "[REDACTED]"


def test_redact_pass_command():
    assert redact_line("PASS labpass") == "[REDACTED]"


def test_non_auth_line_untouched():
    assert redact_line("EHLO mail.lab.test") == "EHLO mail.lab.test"
    assert redact_line("250 2.1.0 Ok") == "250 2.1.0 Ok"


def test_redact_lines_masks_auth_login_and_continuation():
    lines = [
        "EHLO mail.lab.test",
        "AUTH LOGIN",
        "bGFidXNlcg==",
        "bGFicGFzcw==",
        "235 2.7.0 Authentication successful",
    ]
    assert redact_lines(lines) == [
        "EHLO mail.lab.test",
        "[REDACTED]",
        "[REDACTED]",
        "[REDACTED]",
        "235 2.7.0 Authentication successful",
    ]


def test_redact_lines_masks_user_pass_pair():
    lines = ["USER labuser", "PASS labpass", "+OK Logged in."]
    result = redact_lines(lines)
    assert result == ["[REDACTED]", "[REDACTED]", "+OK Logged in."]
