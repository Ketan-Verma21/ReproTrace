from reprotrace.capture.redact import (
    REDACTED,
    is_secret_key,
    looks_like_token,
    redact_env,
    redact_value,
)


def test_secret_key_names_are_detected_case_insensitively() -> None:
    for key in ["API_KEY", "github_token", "DB_PASSWORD", "MY_SECRET", "AWS_CREDENTIALS"]:
        assert is_secret_key(key), key
    for key in ["PATH", "HOME", "TZ", "LANG"]:
        assert not is_secret_key(key), key


def test_token_like_values_are_detected() -> None:
    assert looks_like_token("ghp_" + "a1" * 18)
    assert looks_like_token("sk-" + "abcDEF123_" * 3)
    assert looks_like_token("AKIA" + "ABCDEFGHIJ123456")
    assert looks_like_token("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8")


def test_paths_and_plain_values_are_not_tokens() -> None:
    assert not looks_like_token("/home/someuser/Code/Python/Reprotrace/project-2026")
    assert not looks_like_token("/usr/local/bin:/usr/bin:/bin:/home/someuser/.local/bin")
    assert not looks_like_token("Asia/Kolkata")
    assert not looks_like_token("en_US.UTF-8")


def test_url_password_is_redacted_but_rest_kept() -> None:
    value = "https://alice:hunter2@example.com/repo.git"
    assert redact_value(value) == f"https://alice:{REDACTED}@example.com/repo.git"


def test_redact_env_redacts_by_key_and_value_and_sorts() -> None:
    env = {
        "TZ": "UTC",
        "API_KEY": "short",
        "SOME_VAR": "ghp_" + "x9" * 18,
        "PATH": "/usr/bin:/bin",
    }
    result = redact_env(env)
    assert list(result) == ["API_KEY", "PATH", "SOME_VAR", "TZ"]
    assert result["API_KEY"] == REDACTED
    assert result["SOME_VAR"] == REDACTED
    assert result["TZ"] == "UTC"
    assert result["PATH"] == "/usr/bin:/bin"


def test_redact_env_does_not_modify_input() -> None:
    env = {"API_KEY": "value"}
    redact_env(env)
    assert env == {"API_KEY": "value"}
