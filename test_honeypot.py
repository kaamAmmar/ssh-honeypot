import json

import paramiko
import pytest

import honeypot


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    path = tmp_path / "attempts.jsonl"
    monkeypatch.setattr(honeypot, "LOG_FILE", str(path))
    return path


def test_clean_truncates_to_100_chars():
    assert len(honeypot.clean("A" * 300)) == 100


def test_clean_accepts_non_text():
    assert honeypot.clean(12345) == "12345"


def test_auth_always_fails(log_file):
    server = honeypot.FakeServer("127.0.0.1")
    passwords = ["", "admin", "root", "123456", "A" * 300, "' OR 1=1 --"]
    for pwd in passwords:
        assert server.check_auth_password("root", pwd) == paramiko.AUTH_FAILED


def test_only_password_auth_is_offered():
    server = honeypot.FakeServer("127.0.0.1")
    assert server.get_allowed_auths("root") == "password"


def test_attempt_is_logged(log_file):
    honeypot.log_attempt("10.0.0.1", "root", "123456")
    entry = json.loads(log_file.read_text().strip())
    assert entry["ip"] == "10.0.0.1"
    assert entry["user"] == "root"
    assert entry["password"] == "123456"
    assert "time" in entry


def test_long_password_is_truncated_in_log(log_file):
    honeypot.log_attempt("10.0.0.1", "root", "A" * 300)
    entry = json.loads(log_file.read_text().strip())
    assert len(entry["password"]) == 100


def test_one_line_per_attempt(log_file):
    for i in range(5):
        honeypot.log_attempt("10.0.0.1", "root", f"pass{i}")
    assert len(log_file.read_text().splitlines()) == 5
