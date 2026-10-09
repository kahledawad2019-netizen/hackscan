from __future__ import annotations

import ast
from itertools import permutations

from hackscan.core.redact import REDACTED, mask_secret_literals, redact_text, secret_literal_values


def test_equal_length_secrets_redact_in_stable_order():
    secrets = ("ABCDE", "BCDEF", "XYZAB")
    for ordered in permutations(secrets):
        assert redact_text("ABCDEF", ordered, literals=False) == f"{REDACTED}F"
        assert redact_text("ABCDEF", set(ordered), literals=False) == f"{REDACTED}F"


def test_only_secret_like_source_values_become_report_wide_secrets():
    source = (
        'token_type = "Bearer"\n'
        'auth_mode = "basic"\n'
        'api_key = "password"\n'
        'api_token = "secret-abc123"\n'
        'password = "hunter2hunter2"\n'
        'auth_key = "correcthorsebatterystaple"\n'
    )
    tree = ast.parse(source)
    assert "Bearer" not in mask_secret_literals(source, tree)
    assert secret_literal_values(tree) == {
        "secret-abc123",
        "hunter2hunter2",
        "correcthorsebatterystaple",
    }
