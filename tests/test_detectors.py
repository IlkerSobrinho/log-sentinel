from pathlib import Path

from logsentinel.detectors import detect_ssh, detect_web
from logsentinel.parsers import parse_ssh, parse_web

S = Path(__file__).resolve().parent.parent / "samples"


def lines(n):
    return (S / n).read_text(encoding="utf-8").splitlines()


def test_ssh_parse_counts():
    ev = list(parse_ssh(lines("auth.log"), 2026))
    assert len(ev) == 10
    assert sum(e.kind == "accepted" for e in ev) == 2


def test_ssh_bruteforce_and_compromise():
    rules = {a.rule for a in detect_ssh(list(parse_ssh(lines("auth.log"), 2026)))}
    assert {"ssh_bruteforce", "ssh_success_after_bruteforce", "ssh_user_enumeration", "ssh_root_login"} <= rules


def test_ssh_legit_user_not_flagged():
    alerts = detect_ssh(list(parse_ssh(lines("auth.log"), 2026)))
    assert all(a.ip != "192.168.0.10" for a in alerts)


def test_web_payloads_and_ua():
    alerts = detect_web(list(parse_web(lines("access.log"))))
    rules = {(a.ip, a.rule) for a in alerts}
    assert ("198.51.100.7", "web_malicious_payload") in rules
    assert ("198.51.100.7", "web_scanner_ua") in rules
    assert all(a.ip != "192.0.2.55" for a in alerts)
