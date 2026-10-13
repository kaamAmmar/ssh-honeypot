import json

import report

SAMPLE = [
    {"time": "2026-10-13T07:58:10+00:00", "ip": "192.168.75.128",
     "user": "admin", "password": "123456"},
    {"time": "2026-10-13T07:58:40+00:00", "ip": "192.168.75.128",
     "user": "root", "password": "123456"},
    {"time": "2026-10-13T07:59:05+00:00", "ip": "192.168.75.128",
     "user": "admin", "password": "azerty"},
]


def test_mask_ip():
    assert report.mask_ip("192.168.75.128") == "192.168.x.x"


def test_mask_ip_invalid_value():
    assert report.mask_ip("n'importe quoi") == "masquee"


def test_top_counts_correctly():
    assert report.top(SAMPLE, "password", 1) == [("123456", 2)]
    assert report.top(SAMPLE, "user", 1) == [("admin", 2)]


def test_per_minute_groups_by_minute():
    assert report.per_minute(SAMPLE) == [
        ("2026-10-13T07:58", 2),
        ("2026-10-13T07:59", 1),
    ]


def test_load_attempts_ignores_bad_lines(tmp_path):
    path = tmp_path / "attempts.jsonl"
    good = json.dumps(SAMPLE[0])
    path.write_text(good + "\npas du json\n\n" + good + "\n")
    assert len(report.load_attempts(str(path))) == 2


def test_html_report_escapes_and_masks(tmp_path):
    attempts = [{"time": "2026-10-13T07:58:00+00:00", "ip": "1.2.3.4",
                 "user": "<script>alert(1)</script>", "password": "x"}]
    out = tmp_path / "report.html"
    report.make_html(attempts, out_path=str(out))
    content = out.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in content
    assert "<script>" not in content
    assert "1.2.3.4" not in content


def test_dashboard_png_is_created(tmp_path):
    out = tmp_path / "dashboard.png"
    report.make_dashboard(SAMPLE, out_path=str(out))
    assert out.exists()
